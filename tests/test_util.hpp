#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "netaudit/log.hpp"
#include "netaudit/packet.hpp"
#include "netaudit/reassembly.hpp"

namespace netaudit::test {

constexpr std::uint32_t ip(int a, int b, int c, int d) {
    return (std::uint32_t(a) << 24) | (std::uint32_t(b) << 16) | (std::uint32_t(c) << 8) |
           std::uint32_t(d);
}

inline void put16(std::vector<std::uint8_t>& v, std::size_t at, std::uint16_t x) {
    v[at] = static_cast<std::uint8_t>(x >> 8);
    v[at + 1] = static_cast<std::uint8_t>(x);
}

inline void put32(std::vector<std::uint8_t>& v, std::size_t at, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) v[at + i] = static_cast<std::uint8_t>(x >> (24 - 8 * i));
}

// Ethernet + IPv4 + TCP frame with the given payload (checksums left zero).
inline std::vector<std::uint8_t> make_frame(Endpoint src, Endpoint dst, std::uint32_t seq,
                                            std::uint32_t ack, std::uint8_t flags,
                                            const std::string& payload = "") {
    std::vector<std::uint8_t> f(14 + 20 + 20 + payload.size(), 0);
    put16(f, 12, 0x0800);
    std::size_t ipo = 14;
    f[ipo] = 0x45;
    put16(f, ipo + 2, static_cast<std::uint16_t>(20 + 20 + payload.size()));
    put16(f, ipo + 6, 0x4000);  // DF
    f[ipo + 8] = 64;
    f[ipo + 9] = 6;
    put32(f, ipo + 12, src.ip);
    put32(f, ipo + 16, dst.ip);
    std::size_t t = ipo + 20;
    put16(f, t, src.port);
    put16(f, t + 2, dst.port);
    put32(f, t + 4, seq);
    put32(f, t + 8, ack);
    f[t + 12] = 5 << 4;
    f[t + 13] = flags;
    put16(f, t + 14, 65535);
    std::copy(payload.begin(), payload.end(), f.begin() + t + 20);
    return f;
}

// Builds TcpSegments directly, bypassing the decoder. Keeps payload storage alive.
class SegmentBuilder {
public:
    TcpSegment make(Endpoint src, Endpoint dst, std::uint32_t seq, std::uint8_t flags,
                    const std::string& payload = "", TimestampUs ts = 0) {
        storage_.push_back(std::make_unique<std::string>(payload));
        TcpSegment s;
        s.ts = ts;
        s.src = src;
        s.dst = dst;
        s.seq = seq;
        s.flags = flags;
        s.payload = reinterpret_cast<const std::uint8_t*>(storage_.back()->data());
        s.payload_len = storage_.back()->size();
        return s;
    }

private:
    std::vector<std::unique_ptr<std::string>> storage_;
};

// Records everything a reassembler hands to a connection.
struct Recording {
    ConnectionInfo info;
    std::string data[2];
    std::vector<std::uint64_t> gaps[2];
    bool closed = false;
    CloseReason reason = CloseReason::Shutdown;
    int data_calls = 0;
};

class RecordingHandler : public StreamHandler {
public:
    explicit RecordingHandler(std::shared_ptr<Recording> rec, std::size_t stop_after = 0)
        : rec_(std::move(rec)), stop_after_(stop_after) {}

    void on_data(Direction dir, const std::uint8_t* data, std::size_t len,
                 TimestampUs) override {
        rec_->data[index_of(dir)].append(reinterpret_cast<const char*>(data), len);
        ++rec_->data_calls;
    }
    void on_gap(Direction dir, std::uint64_t bytes, TimestampUs) override {
        rec_->gaps[index_of(dir)].push_back(bytes);
    }
    void on_close(CloseReason reason, TimestampUs) override {
        rec_->closed = true;
        rec_->reason = reason;
    }
    bool wants_data() const override {
        return stop_after_ == 0 ||
               rec_->data[0].size() + rec_->data[1].size() < stop_after_;
    }

private:
    std::shared_ptr<Recording> rec_;
    std::size_t stop_after_;
};

class CollectingSink : public EventSink {
public:
    void emit(const LogRecord& r) override { records.push_back(r); }
    std::vector<LogRecord> records;
};

}  // namespace netaudit::test
