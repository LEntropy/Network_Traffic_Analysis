#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace netaudit {

// Microseconds since the Unix epoch, taken from the capture timestamp.
using TimestampUs = std::int64_t;

struct Endpoint {
    std::uint32_t ip = 0;  // IPv4, host byte order
    std::uint16_t port = 0;

    bool operator==(const Endpoint& o) const { return ip == o.ip && port == o.port; }
    bool operator!=(const Endpoint& o) const { return !(*this == o); }
    bool operator<(const Endpoint& o) const { return ip != o.ip ? ip < o.ip : port < o.port; }
};

std::string ip_to_string(std::uint32_t ip);
std::string to_string(const Endpoint& ep);

// RFC 3339 UTC with microseconds, e.g. 2026-10-23T08:00:00.123456Z
std::string format_timestamp(TimestampUs ts);

// Direction-independent key: both directions of one connection map to the same key.
struct FlowKey {
    Endpoint lo;
    Endpoint hi;

    static FlowKey from(const Endpoint& a, const Endpoint& b) {
        return a < b ? FlowKey{a, b} : FlowKey{b, a};
    }
    bool operator==(const FlowKey& o) const { return lo == o.lo && hi == o.hi; }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const noexcept {
        std::uint64_t a = (std::uint64_t{k.lo.ip} << 16) | k.lo.port;
        std::uint64_t b = (std::uint64_t{k.hi.ip} << 16) | k.hi.port;
        std::uint64_t h = a * 0x9E3779B97F4A7C15ULL;
        h ^= b + 0x632BE59BD9B4E019ULL + (h << 6) + (h >> 2);
        return static_cast<std::size_t>(h ^ (h >> 31));
    }
};

enum class Direction : std::uint8_t { ClientToServer = 0, ServerToClient = 1 };

inline std::size_t index_of(Direction d) { return static_cast<std::size_t>(d); }

}  // namespace netaudit
