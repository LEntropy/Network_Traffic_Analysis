#include "netaudit/packet.hpp"

namespace netaudit {

namespace {

constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
constexpr std::uint16_t kEtherTypeVlan = 0x8100;
constexpr std::uint16_t kEtherTypeQinQ = 0x88A8;
constexpr std::uint8_t kProtoTcp = 6;

std::uint16_t be16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

std::uint32_t be32(const std::uint8_t* p) {
    return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) |
           (std::uint32_t{p[2]} << 8) | std::uint32_t{p[3]};
}

DecodeStatus decode_ipv4(const std::uint8_t* p, std::size_t len, TimestampUs ts,
                         TcpSegment& out) {
    if (len < 20) return DecodeStatus::Truncated;
    if ((p[0] >> 4) != 4) return DecodeStatus::NotIpv4;

    const std::size_t ihl = std::size_t{p[0] & 0x0Fu} * 4;
    if (ihl < 20) return DecodeStatus::Malformed;
    if (len < ihl) return DecodeStatus::Truncated;

    // The IPv4 total length bounds the payload; anything after it is link padding.
    const std::size_t total = be16(p + 2);
    if (total < ihl) return DecodeStatus::Malformed;
    if (total > len) return DecodeStatus::Truncated;

    const std::uint16_t frag = be16(p + 6);
    const bool more_fragments = (frag & 0x2000u) != 0;
    const bool nonzero_offset = (frag & 0x1FFFu) != 0;
    if (more_fragments || nonzero_offset) return DecodeStatus::Fragment;

    if (p[9] != kProtoTcp) return DecodeStatus::NotTcp;

    const std::uint8_t* t = p + ihl;
    const std::size_t tcp_len = total - ihl;
    if (tcp_len < 20) return DecodeStatus::Truncated;

    const std::size_t data_offset = std::size_t{static_cast<std::uint8_t>(t[12] >> 4)} * 4;
    if (data_offset < 20 || data_offset > tcp_len) return DecodeStatus::Malformed;

    out.ts = ts;
    out.src = Endpoint{be32(p + 12), be16(t)};
    out.dst = Endpoint{be32(p + 16), be16(t + 2)};
    out.seq = be32(t + 4);
    out.ack = be32(t + 8);
    out.flags = t[13];
    out.payload = t + data_offset;
    out.payload_len = tcp_len - data_offset;
    return DecodeStatus::Ok;
}

}  // namespace

std::optional<LinkType> link_type_from_dlt(int dlt) {
    switch (dlt) {
        case 1:  // DLT_EN10MB
            return LinkType::Ethernet;
        case 113:  // DLT_LINUX_SLL ("any" interface)
            return LinkType::LinuxSll;
        case 12:   // DLT_RAW on most platforms
        case 14:   // DLT_RAW on OpenBSD
        case 101:  // LINKTYPE_RAW
        case 228:  // LINKTYPE_IPV4
            return LinkType::RawIp;
        default:
            return std::nullopt;
    }
}

const char* to_string(DecodeStatus s) {
    switch (s) {
        case DecodeStatus::Ok: return "ok";
        case DecodeStatus::Truncated: return "truncated";
        case DecodeStatus::NotIpv4: return "not_ipv4";
        case DecodeStatus::NotTcp: return "not_tcp";
        case DecodeStatus::Fragment: return "fragment";
        case DecodeStatus::Malformed: return "malformed";
    }
    return "unknown";
}

DecodeStatus decode_frame(LinkType link, const std::uint8_t* data, std::size_t len,
                          TimestampUs ts, TcpSegment& out) {
    switch (link) {
        case LinkType::RawIp:
            return decode_ipv4(data, len, ts, out);

        case LinkType::LinuxSll: {
            if (len < 16) return DecodeStatus::Truncated;
            if (be16(data + 14) != kEtherTypeIpv4) return DecodeStatus::NotIpv4;
            return decode_ipv4(data + 16, len - 16, ts, out);
        }

        case LinkType::Ethernet: {
            if (len < 14) return DecodeStatus::Truncated;
            std::size_t off = 12;
            std::uint16_t ether_type = be16(data + off);
            // Up to two stacked VLAN tags (802.1Q / 802.1ad).
            for (int tags = 0; tags < 2 && (ether_type == kEtherTypeVlan ||
                                            ether_type == kEtherTypeQinQ);
                 ++tags) {
                off += 4;
                if (len < off + 2) return DecodeStatus::Truncated;
                ether_type = be16(data + off);
            }
            if (ether_type != kEtherTypeIpv4) return DecodeStatus::NotIpv4;
            off += 2;
            return decode_ipv4(data + off, len - off, ts, out);
        }
    }
    return DecodeStatus::Malformed;
}

}  // namespace netaudit
