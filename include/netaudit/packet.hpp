#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "netaudit/net.hpp"

namespace netaudit {

namespace tcp_flags {
constexpr std::uint8_t FIN = 0x01;
constexpr std::uint8_t SYN = 0x02;
constexpr std::uint8_t RST = 0x04;
constexpr std::uint8_t PSH = 0x08;
constexpr std::uint8_t ACK = 0x10;
}  // namespace tcp_flags

// A decoded TCP segment. `payload` points into the caller's frame buffer and is only
// valid for the duration of the callback that received it.
struct TcpSegment {
    TimestampUs ts = 0;
    Endpoint src;
    Endpoint dst;
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;
    std::uint8_t flags = 0;
    const std::uint8_t* payload = nullptr;
    std::size_t payload_len = 0;

    bool has(std::uint8_t f) const { return (flags & f) != 0; }
};

enum class LinkType { Ethernet, LinuxSll, RawIp };

// Maps a libpcap DLT_/LINKTYPE_ value to a supported link layer.
std::optional<LinkType> link_type_from_dlt(int dlt);

enum class DecodeStatus {
    Ok,
    Truncated,  // frame shorter than its headers claim (snaplen or corrupt)
    NotIpv4,
    NotTcp,
    Fragment,   // IPv4 fragment; reassembly of IP fragments is not implemented
    Malformed,
};

const char* to_string(DecodeStatus s);

// Decodes link -> IPv4 -> TCP. Ethernet padding is trimmed using the IPv4 total length.
// Checksums are not verified because capture on the sending host usually sees
// offloaded (not yet computed) checksums.
DecodeStatus decode_frame(LinkType link, const std::uint8_t* data, std::size_t len,
                          TimestampUs ts, TcpSegment& out);

}  // namespace netaudit
