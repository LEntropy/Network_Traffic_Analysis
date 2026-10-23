#include "netaudit/reassembly.hpp"

#include <algorithm>
#include <iterator>
#include <utility>

namespace netaudit {

const char* to_string(CloseReason r) {
    switch (r) {
        case CloseReason::Fin: return "fin";
        case CloseReason::Reset: return "reset";
        case CloseReason::Timeout: return "timeout";
        case CloseReason::Reused: return "reused";
        case CloseReason::Shutdown: return "shutdown";
    }
    return "unknown";
}

TcpReassembler::TcpReassembler(HandlerFactory factory, ReassemblyConfig config)
    : factory_(std::move(factory)), config_(config) {}

TcpReassembler::~TcpReassembler() = default;

void TcpReassembler::process(const TcpSegment& seg) {
    using namespace tcp_flags;
    ++stats_.segments;

    const FlowKey key = FlowKey::from(seg.src, seg.dst);
    auto it = flows_.find(key);

    // A new SYN on a tracked 4-tuple with a different ISN means the port pair was reused
    // before we saw the old connection close.
    if (it != flows_.end() && seg.has(SYN) && !seg.has(ACK)) {
        const Flow& old = it->second;
        const HalfStream& c = old.half[index_of(Direction::ClientToServer)];
        if (seg.src != old.info.client || (c.initialized && seg.seq + 1 != c.isn)) {
            close_flow(it, CloseReason::Reused, seg.ts);
            it = flows_.end();
        }
    }

    if (it == flows_.end()) {
        if (seg.has(RST)) return;
        // Stray ACKs/FINs of connections we are not tracking carry nothing to rebuild.
        if (!seg.has(SYN) && seg.payload_len == 0) return;
        if (flows_.size() >= config_.max_flows) {
            ++stats_.flows_rejected;
            return;
        }
        it = create_flow(key, seg);
    }

    Flow& flow = it->second;
    flow.last_seen = seg.ts;

    if (seg.has(RST)) {
        close_flow(it, CloseReason::Reset, seg.ts);
        return;
    }

    const Direction dir =
        seg.src == flow.info.client ? Direction::ClientToServer : Direction::ServerToClient;
    ingest(flow, dir, seg);

    if (flow.half[0].finished && flow.half[1].finished) {
        close_flow(it, CloseReason::Fin, seg.ts);
    }
}

TcpReassembler::FlowMap::iterator TcpReassembler::create_flow(const FlowKey& key,
                                                              const TcpSegment& seg) {
    using namespace tcp_flags;
    ConnectionInfo info;
    info.start = seg.ts;
    if (seg.has(SYN) && !seg.has(ACK)) {
        info.client = seg.src;
        info.server = seg.dst;
    } else if (seg.has(SYN) && seg.has(ACK)) {
        info.client = seg.dst;
        info.server = seg.src;
    } else {
        // Picked up mid-stream: assume the lower port is the service port.
        info.midstream = true;
        const bool src_is_server = seg.src.port < seg.dst.port;
        info.client = src_is_server ? seg.dst : seg.src;
        info.server = src_is_server ? seg.src : seg.dst;
    }

    Flow flow;
    flow.info = info;
    flow.last_seen = seg.ts;
    flow.handler = factory_ ? factory_(info) : nullptr;
    flow.ignored = flow.handler == nullptr;
    ++stats_.flows_created;
    return flows_.emplace(key, std::move(flow)).first;
}

void TcpReassembler::ingest(Flow& flow, Direction dir, const TcpSegment& seg) {
    using namespace tcp_flags;
    HalfStream& h = flow.half[index_of(dir)];

    std::uint32_t seq = seg.seq;
    if (seg.has(SYN)) {
        seq += 1;  // the SYN itself occupies one sequence number
        if (!h.initialized) {
            h.isn = seq;
            h.initialized = true;
        }
    }
    if (!h.initialized) {
        if (seg.payload_len == 0 && !seg.has(FIN)) return;
        h.isn = seq;
        h.initialized = true;
    }

    // Distance from the next expected byte, interpreted as a signed 32-bit value so that
    // it stays correct across sequence number wraparound.
    const std::uint32_t next_wire = h.isn + static_cast<std::uint32_t>(h.next);
    const std::int64_t delta = static_cast<std::int32_t>(seq - next_wire);
    std::int64_t offset = static_cast<std::int64_t>(h.next) + delta;

    const std::uint8_t* data = seg.payload;
    std::size_t len = seg.payload_len;
    const std::int64_t end = offset + static_cast<std::int64_t>(len);

    if (seg.has(FIN) && !h.fin_seen && end >= 0) {
        h.fin_seen = true;
        h.fin_offset = static_cast<std::uint64_t>(end);
    }

    if (offset < 0) {
        // Bytes from before the point where we started tracking this stream.
        const std::size_t skip = std::min(len, static_cast<std::size_t>(-offset));
        stats_.retransmitted_bytes += skip;
        data += skip;
        len -= skip;
        offset = 0;
    }

    if (!flow.ignored && len > 0) {
        insert(flow, dir, static_cast<std::uint64_t>(offset), data, len, seg.ts);
    }

    if (h.fin_seen && (flow.ignored || h.next >= h.fin_offset)) h.finished = true;
}

void TcpReassembler::insert(Flow& flow, Direction dir, std::uint64_t offset,
                            const std::uint8_t* data, std::size_t len, TimestampUs ts) {
    HalfStream& h = flow.half[index_of(dir)];

    if (offset + len <= h.next) {
        stats_.retransmitted_bytes += len;
        return;
    }
    if (offset < h.next) {
        const std::size_t skip = static_cast<std::size_t>(h.next - offset);
        stats_.overlap_bytes += skip;
        data += skip;
        len -= skip;
        offset = h.next;
    }

    if (offset == h.next) {
        deliver(flow, dir, data, len, ts);
        drain_pending(flow, dir, ts);
        return;
    }

    ++stats_.out_of_order_segments;
    auto& slot = h.pending[offset];
    if (slot.size() < len) {
        h.pending_bytes += len - slot.size();
        slot.assign(data, data + len);
    }

    // The missing range is unlikely to arrive any more; give up on it rather than
    // buffering without bound.
    while (!flow.ignored && h.pending_bytes > config_.max_pending_bytes) {
        skip_to_pending(flow, dir, ts);
    }
}

void TcpReassembler::deliver(Flow& flow, Direction dir, const std::uint8_t* data,
                             std::size_t len, TimestampUs ts) {
    HalfStream& h = flow.half[index_of(dir)];
    h.next += len;
    stats_.delivered_bytes += len;
    flow.handler->on_data(dir, data, len, ts);
    if (!flow.handler->wants_data()) stop_flow(flow);
}

void TcpReassembler::drain_pending(Flow& flow, Direction dir, TimestampUs ts) {
    HalfStream& h = flow.half[index_of(dir)];
    while (!flow.ignored && !h.pending.empty()) {
        auto first = h.pending.begin();
        const std::uint64_t offset = first->first;
        if (offset > h.next) break;

        // Move the bytes out first: deliver() may stop the flow and clear `pending`.
        std::vector<std::uint8_t> buf = std::move(first->second);
        h.pending_bytes -= buf.size();
        h.pending.erase(first);

        if (offset + buf.size() <= h.next) {
            stats_.retransmitted_bytes += buf.size();
            continue;
        }
        const std::size_t skip = static_cast<std::size_t>(h.next - offset);
        stats_.overlap_bytes += skip;
        deliver(flow, dir, buf.data() + skip, buf.size() - skip, ts);
    }
}

void TcpReassembler::skip_to_pending(Flow& flow, Direction dir, TimestampUs ts) {
    HalfStream& h = flow.half[index_of(dir)];
    if (h.pending.empty()) return;

    const std::uint64_t target = h.pending.begin()->first;
    const std::uint64_t gap = target - h.next;
    ++stats_.gap_events;
    stats_.gap_bytes += gap;
    h.next = target;
    flow.handler->on_gap(dir, gap, ts);
    if (!flow.handler->wants_data()) {
        stop_flow(flow);
        return;
    }
    drain_pending(flow, dir, ts);
}

void TcpReassembler::stop_flow(Flow& flow) {
    flow.ignored = true;
    for (HalfStream& h : flow.half) {
        h.pending.clear();
        h.pending_bytes = 0;
        if (h.fin_seen) h.finished = true;
    }
}

void TcpReassembler::close_flow(FlowMap::iterator it, CloseReason reason, TimestampUs ts) {
    Flow& flow = it->second;
    // Deliver whatever is still buffered, reporting the holes in front of it.
    for (Direction dir : {Direction::ClientToServer, Direction::ServerToClient}) {
        while (!flow.ignored && !flow.half[index_of(dir)].pending.empty()) {
            skip_to_pending(flow, dir, ts);
        }
    }
    if (flow.handler) flow.handler->on_close(reason, ts);
    flows_.erase(it);
    ++stats_.flows_closed;
}

void TcpReassembler::expire_idle(TimestampUs now) {
    for (auto it = flows_.begin(); it != flows_.end();) {
        auto next = std::next(it);
        if (now - it->second.last_seen > config_.idle_timeout_us) {
            close_flow(it, CloseReason::Timeout, now);
        }
        it = next;
    }
}

void TcpReassembler::close_all(TimestampUs now) {
    while (!flows_.empty()) close_flow(flows_.begin(), CloseReason::Shutdown, now);
}

}  // namespace netaudit
