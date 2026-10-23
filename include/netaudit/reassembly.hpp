#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

#include "netaudit/net.hpp"
#include "netaudit/packet.hpp"

namespace netaudit {

enum class CloseReason { Fin, Reset, Timeout, Reused, Shutdown };

const char* to_string(CloseReason r);

struct ConnectionInfo {
    Endpoint client;
    Endpoint server;
    TimestampUs start = 0;
    // True when the 3-way handshake was not observed and client/server were guessed.
    bool midstream = false;
};

// Receives the in-order byte stream of both directions of one TCP connection.
class StreamHandler {
public:
    virtual ~StreamHandler() = default;

    virtual void on_data(Direction dir, const std::uint8_t* data, std::size_t len,
                         TimestampUs ts) = 0;

    // `bytes` were never captured in this direction; the stream continues after the hole.
    virtual void on_gap(Direction dir, std::uint64_t bytes, TimestampUs ts) = 0;

    virtual void on_close(CloseReason reason, TimestampUs ts) = 0;

    // Returning false makes the reassembler stop buffering and delivering this flow.
    virtual bool wants_data() const { return true; }
};

// Returns nullptr to ignore a connection entirely.
using HandlerFactory = std::function<std::unique_ptr<StreamHandler>(const ConnectionInfo&)>;

struct ReassemblyConfig {
    // Out-of-order bytes buffered per direction before the missing range is declared a gap.
    std::size_t max_pending_bytes = 1 << 20;
    TimestampUs idle_timeout_us = 120LL * 1000 * 1000;
    std::size_t max_flows = 100000;
};

struct ReassemblyStats {
    std::uint64_t segments = 0;
    std::uint64_t flows_created = 0;
    std::uint64_t flows_closed = 0;
    std::uint64_t flows_rejected = 0;  // flow table full
    std::uint64_t delivered_bytes = 0;
    std::uint64_t retransmitted_bytes = 0;
    std::uint64_t overlap_bytes = 0;
    std::uint64_t out_of_order_segments = 0;
    std::uint64_t gap_events = 0;
    std::uint64_t gap_bytes = 0;
};

// Rebuilds both byte streams of each TCP connection from captured segments, handling
// out-of-order arrival, retransmission, partial overlap and 32-bit sequence wraparound.
//
// Sequence numbers are mapped to 64-bit stream offsets relative to the initial
// sequence number, so ordering never has to compare wrapped 32-bit values.
class TcpReassembler {
public:
    explicit TcpReassembler(HandlerFactory factory, ReassemblyConfig config = {});
    ~TcpReassembler();

    TcpReassembler(const TcpReassembler&) = delete;
    TcpReassembler& operator=(const TcpReassembler&) = delete;

    void process(const TcpSegment& seg);

    // Closes connections that have seen no segment for `idle_timeout_us`.
    void expire_idle(TimestampUs now);

    // Closes every open connection, e.g. at the end of a capture file.
    void close_all(TimestampUs now);

    std::size_t active_flows() const { return flows_.size(); }
    const ReassemblyStats& stats() const { return stats_; }

private:
    struct HalfStream {
        bool initialized = false;
        std::uint32_t isn = 0;        // wire sequence number of stream offset 0
        std::uint64_t next = 0;       // next expected stream offset
        std::map<std::uint64_t, std::vector<std::uint8_t>> pending;  // offset -> bytes
        std::size_t pending_bytes = 0;
        bool fin_seen = false;
        std::uint64_t fin_offset = 0;
        bool finished = false;
    };

    struct Flow {
        ConnectionInfo info;
        HalfStream half[2];
        std::unique_ptr<StreamHandler> handler;
        TimestampUs last_seen = 0;
        bool ignored = false;
    };

    using FlowMap = std::unordered_map<FlowKey, Flow, FlowKeyHash>;

    FlowMap::iterator create_flow(const FlowKey& key, const TcpSegment& seg);
    void ingest(Flow& flow, Direction dir, const TcpSegment& seg);
    void insert(Flow& flow, Direction dir, std::uint64_t offset, const std::uint8_t* data,
                std::size_t len, TimestampUs ts);
    void deliver(Flow& flow, Direction dir, const std::uint8_t* data, std::size_t len,
                 TimestampUs ts);
    void drain_pending(Flow& flow, Direction dir, TimestampUs ts);
    void skip_to_pending(Flow& flow, Direction dir, TimestampUs ts);
    void stop_flow(Flow& flow);
    void close_flow(FlowMap::iterator it, CloseReason reason, TimestampUs ts);

    HandlerFactory factory_;
    ReassemblyConfig config_;
    ReassemblyStats stats_;
    FlowMap flows_;
};

}  // namespace netaudit
