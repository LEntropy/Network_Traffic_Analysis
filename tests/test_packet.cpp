#include <gtest/gtest.h>

#include "netaudit/packet.hpp"
#include "test_util.hpp"

using namespace netaudit;
using namespace netaudit::test;

namespace {

const Endpoint kClient{ip(10, 0, 0, 2), 51000};
const Endpoint kServer{ip(93, 184, 216, 34), 80};

}  // namespace

TEST(Decode, EthernetIpv4Tcp) {
    auto f = make_frame(kClient, kServer, 1000, 2000, tcp_flags::ACK | tcp_flags::PSH, "hello");
    TcpSegment s;
    ASSERT_EQ(decode_frame(LinkType::Ethernet, f.data(), f.size(), 42, s), DecodeStatus::Ok);
    EXPECT_EQ(s.src, kClient);
    EXPECT_EQ(s.dst, kServer);
    EXPECT_EQ(s.seq, 1000u);
    EXPECT_EQ(s.ack, 2000u);
    EXPECT_TRUE(s.has(tcp_flags::PSH));
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(s.payload), s.payload_len), "hello");
    EXPECT_EQ(s.ts, 42);
}

TEST(Decode, EthernetPaddingIsNotPayload) {
    // Minimum Ethernet frames are padded to 60 bytes; the padding must not leak into TCP.
    auto f = make_frame(kClient, kServer, 1, 0, tcp_flags::ACK);
    f.resize(60, 0xAA);
    TcpSegment s;
    ASSERT_EQ(decode_frame(LinkType::Ethernet, f.data(), f.size(), 0, s), DecodeStatus::Ok);
    EXPECT_EQ(s.payload_len, 0u);
}

TEST(Decode, VlanTagged) {
    auto plain = make_frame(kClient, kServer, 7, 0, tcp_flags::ACK, "x");
    std::vector<std::uint8_t> f(plain.begin(), plain.begin() + 12);
    f.insert(f.end(), {0x81, 0x00, 0x00, 0x64});  // 802.1Q, VLAN 100
    f.insert(f.end(), plain.begin() + 12, plain.end());
    TcpSegment s;
    ASSERT_EQ(decode_frame(LinkType::Ethernet, f.data(), f.size(), 0, s), DecodeStatus::Ok);
    EXPECT_EQ(s.seq, 7u);
    EXPECT_EQ(s.payload_len, 1u);
}

TEST(Decode, RawIp) {
    auto f = make_frame(kClient, kServer, 7, 0, tcp_flags::ACK, "abc");
    TcpSegment s;
    ASSERT_EQ(decode_frame(LinkType::RawIp, f.data() + 14, f.size() - 14, 0, s),
              DecodeStatus::Ok);
    EXPECT_EQ(s.payload_len, 3u);
}

TEST(Decode, SnaplenCutIsTruncated) {
    auto f = make_frame(kClient, kServer, 7, 0, tcp_flags::ACK, std::string(100, 'a'));
    TcpSegment s;
    EXPECT_EQ(decode_frame(LinkType::Ethernet, f.data(), 80, 0, s), DecodeStatus::Truncated);
    EXPECT_EQ(decode_frame(LinkType::Ethernet, f.data(), 10, 0, s), DecodeStatus::Truncated);
}

TEST(Decode, RejectsNonTcpAndFragments) {
    auto udp = make_frame(kClient, kServer, 0, 0, 0);
    udp[14 + 9] = 17;
    TcpSegment s;
    EXPECT_EQ(decode_frame(LinkType::Ethernet, udp.data(), udp.size(), 0, s),
              DecodeStatus::NotTcp);

    auto frag = make_frame(kClient, kServer, 0, 0, 0, "data");
    put16(frag, 14 + 6, 0x2000);  // more fragments
    EXPECT_EQ(decode_frame(LinkType::Ethernet, frag.data(), frag.size(), 0, s),
              DecodeStatus::Fragment);

    auto arp = make_frame(kClient, kServer, 0, 0, 0);
    put16(arp, 12, 0x0806);
    EXPECT_EQ(decode_frame(LinkType::Ethernet, arp.data(), arp.size(), 0, s),
              DecodeStatus::NotIpv4);
}

TEST(Decode, BadTcpDataOffsetIsMalformed) {
    auto f = make_frame(kClient, kServer, 0, 0, 0, "abcd");
    f[14 + 20 + 12] = 15 << 4;  // 60-byte header in a 24-byte segment
    TcpSegment s;
    EXPECT_EQ(decode_frame(LinkType::Ethernet, f.data(), f.size(), 0, s),
              DecodeStatus::Malformed);
}
