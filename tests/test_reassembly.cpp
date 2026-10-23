#include <gtest/gtest.h>

#include <algorithm>
#include <random>

#include "netaudit/reassembly.hpp"
#include "test_util.hpp"

using namespace netaudit;
using namespace netaudit::test;
using namespace netaudit::tcp_flags;

namespace {

const Endpoint kClient{ip(10, 0, 0, 2), 51000};
const Endpoint kServer{ip(10, 0, 0, 1), 80};

class ReassemblyTest : public ::testing::Test {
protected:
    explicit ReassemblyTest(ReassemblyConfig config = {})
        : reassembler_(
              [this](const ConnectionInfo& info) {
                  auto rec = std::make_shared<Recording>();
                  rec->info = info;
                  recordings_.push_back(rec);
                  return std::make_unique<RecordingHandler>(rec, stop_after_);
              },
              config) {}

    void handshake(std::uint32_t cisn, std::uint32_t sisn) {
        feed(kClient, kServer, cisn, SYN);
        feed(kServer, kClient, sisn, SYN | ACK);
        feed(kClient, kServer, cisn + 1, ACK);
    }

    void feed(Endpoint src, Endpoint dst, std::uint32_t seq, std::uint8_t flags,
              const std::string& payload = "", TimestampUs ts = 0) {
        reassembler_.process(segs_.make(src, dst, seq, flags, payload, ts));
    }

    Recording& rec(std::size_t i = 0) { return *recordings_.at(i); }

    SegmentBuilder segs_;
    std::vector<std::shared_ptr<Recording>> recordings_;
    std::size_t stop_after_ = 0;
    TcpReassembler reassembler_;
};

constexpr std::size_t C2S = 0;
constexpr std::size_t S2C = 1;

}  // namespace

TEST_F(ReassemblyTest, InOrderBothDirections) {
    handshake(1000, 5000);
    feed(kClient, kServer, 1001, ACK | PSH, "GET / HTTP/1.1\r\n");
    feed(kClient, kServer, 1017, ACK | PSH, "\r\n");
    feed(kServer, kClient, 5001, ACK | PSH, "HTTP/1.1 200 OK\r\n");

    ASSERT_EQ(recordings_.size(), 1u);
    EXPECT_EQ(rec().info.client, kClient);
    EXPECT_FALSE(rec().info.midstream);
    EXPECT_EQ(rec().data[C2S], "GET / HTTP/1.1\r\n\r\n");
    EXPECT_EQ(rec().data[S2C], "HTTP/1.1 200 OK\r\n");
}

TEST_F(ReassemblyTest, OutOfOrderIsReordered) {
    handshake(1000, 5000);
    feed(kClient, kServer, 1007, ACK, "world");
    EXPECT_EQ(rec().data[C2S], "");
    feed(kClient, kServer, 1001, ACK, "hello ");
    EXPECT_EQ(rec().data[C2S], "hello world");
    EXPECT_EQ(reassembler_.stats().out_of_order_segments, 1u);
}

TEST_F(ReassemblyTest, RetransmissionIsDeliveredOnce) {
    handshake(1000, 5000);
    feed(kClient, kServer, 1001, ACK, "abc");
    feed(kClient, kServer, 1001, ACK, "abc");
    feed(kClient, kServer, 1004, ACK, "def");
    EXPECT_EQ(rec().data[C2S], "abcdef");
    EXPECT_EQ(reassembler_.stats().retransmitted_bytes, 3u);
}

TEST_F(ReassemblyTest, PartialOverlapIsTrimmed) {
    handshake(1000, 5000);
    feed(kClient, kServer, 1001, ACK, "abcd");
    feed(kClient, kServer, 1003, ACK, "cdefg");  // repacketised retransmission
    EXPECT_EQ(rec().data[C2S], "abcdefg");
    EXPECT_EQ(reassembler_.stats().overlap_bytes, 2u);
}

TEST_F(ReassemblyTest, OverlappingPendingSegments) {
    handshake(1000, 5000);
    feed(kClient, kServer, 1005, ACK, "efgh");
    feed(kClient, kServer, 1003, ACK, "cdef");
    feed(kClient, kServer, 1001, ACK, "ab");
    EXPECT_EQ(rec().data[C2S], "abcdefgh");
}

TEST_F(ReassemblyTest, SequenceWraparound) {
    const std::uint32_t isn = 0xFFFFFFFAu;  // payload starts at 0xFFFFFFFB and wraps
    handshake(isn, 5000);
    feed(kClient, kServer, isn + 1 + 10, ACK, "KLMNO");  // after wrap, out of order
    feed(kClient, kServer, isn + 1, ACK, "ABCDEFGHIJ");  // crosses 2^32
    EXPECT_EQ(rec().data[C2S], "ABCDEFGHIJKLMNO");
}

TEST_F(ReassemblyTest, FinFromBothSidesClosesFlow) {
    handshake(1000, 5000);
    feed(kClient, kServer, 1001, ACK | PSH, "req");
    feed(kServer, kClient, 5001, ACK | PSH | FIN, "resp");
    EXPECT_FALSE(rec().closed);
    feed(kClient, kServer, 1004, ACK | FIN);
    EXPECT_TRUE(rec().closed);
    EXPECT_EQ(rec().reason, CloseReason::Fin);
    EXPECT_EQ(reassembler_.active_flows(), 0u);
}

TEST_F(ReassemblyTest, FinWaitsForMissingData) {
    handshake(1000, 5000);
    feed(kClient, kServer, 1004, ACK | FIN, "def");  // FIN arrives before "abc"
    feed(kServer, kClient, 5001, ACK | FIN);
    EXPECT_FALSE(rec().closed);
    feed(kClient, kServer, 1001, ACK, "abc");
    EXPECT_EQ(rec().data[C2S], "abcdef");
    EXPECT_TRUE(rec().closed);
}

TEST_F(ReassemblyTest, ResetClosesImmediately) {
    handshake(1000, 5000);
    feed(kClient, kServer, 1001, ACK, "x");
    feed(kServer, kClient, 5001, RST);
    EXPECT_TRUE(rec().closed);
    EXPECT_EQ(rec().reason, CloseReason::Reset);
}

TEST_F(ReassemblyTest, MidstreamPickupGuessesServerByPort) {
    feed(kServer, kClient, 777, ACK, "tail of a response");
    ASSERT_EQ(recordings_.size(), 1u);
    EXPECT_TRUE(rec().info.midstream);
    EXPECT_EQ(rec().info.server, kServer);
    EXPECT_EQ(rec().data[S2C], "tail of a response");
}

TEST_F(ReassemblyTest, StrayAckDoesNotCreateFlow) {
    feed(kClient, kServer, 1, ACK);
    feed(kClient, kServer, 1, ACK | FIN);
    EXPECT_TRUE(recordings_.empty());
    EXPECT_EQ(reassembler_.active_flows(), 0u);
}

TEST_F(ReassemblyTest, PortReuseStartsNewConnection) {
    handshake(1000, 5000);
    feed(kClient, kServer, 1001, ACK, "first");
    handshake(90000, 7000);
    feed(kClient, kServer, 90001, ACK, "second");
    ASSERT_EQ(recordings_.size(), 2u);
    EXPECT_EQ(rec(0).reason, CloseReason::Reused);
    EXPECT_EQ(rec(0).data[C2S], "first");
    EXPECT_EQ(rec(1).data[C2S], "second");
}

TEST_F(ReassemblyTest, HandlerCanStopDelivery) {
    stop_after_ = 3;
    handshake(1000, 5000);
    feed(kClient, kServer, 1001, ACK, "abc");
    feed(kClient, kServer, 1004, ACK, "def");
    EXPECT_EQ(rec().data[C2S], "abc");
}

TEST_F(ReassemblyTest, IdleTimeoutClosesFlow) {
    handshake(1000, 5000);
    feed(kClient, kServer, 1001, ACK, "x", 1000000);
    reassembler_.expire_idle(1000000 + 60LL * 1000000);
    EXPECT_FALSE(rec().closed);
    reassembler_.expire_idle(1000000 + 121LL * 1000000);
    EXPECT_TRUE(rec().closed);
    EXPECT_EQ(rec().reason, CloseReason::Timeout);
}

TEST_F(ReassemblyTest, CloseReportsGapBeforeBufferedData) {
    handshake(1000, 5000);
    feed(kClient, kServer, 1001, ACK, "abc");
    feed(kClient, kServer, 1010, ACK, "xyz");  // bytes 1004..1009 never arrive
    reassembler_.close_all(0);
    EXPECT_EQ(rec().data[C2S], "abcxyz");
    ASSERT_EQ(rec().gaps[C2S].size(), 1u);
    EXPECT_EQ(rec().gaps[C2S][0], 6u);
}

namespace {

class SmallBufferTest : public ReassemblyTest {
protected:
    SmallBufferTest() : ReassemblyTest(make_config()) {}
    static ReassemblyConfig make_config() {
        ReassemblyConfig c;
        c.max_pending_bytes = 8;
        return c;
    }
};

}  // namespace

TEST_F(SmallBufferTest, PendingLimitDeclaresGap) {
    handshake(1000, 5000);
    feed(kClient, kServer, 1001, ACK, "ab");
    feed(kClient, kServer, 1010, ACK, "0123");   // hole of 7 bytes, 4 buffered
    feed(kClient, kServer, 1014, ACK, "45678");  // 9 buffered > 8 -> skip the hole
    EXPECT_EQ(rec().data[C2S], "ab012345678");
    ASSERT_EQ(rec().gaps[C2S].size(), 1u);
    EXPECT_EQ(rec().gaps[C2S][0], 7u);
    EXPECT_EQ(reassembler_.stats().gap_bytes, 7u);
}

// Property test: any mix of reordering, duplication and re-segmentation of a stream
// must reproduce exactly the original bytes.
TEST_F(ReassemblyTest, RandomisedReorderingReproducesStream) {
    std::mt19937 rng(12345);
    std::string original;
    for (int i = 0; i < 20000; ++i) original.push_back(static_cast<char>('a' + rng() % 26));

    const std::uint32_t isn = 0xFFFFC000u;  // 16 KiB before the 32-bit wrap
    handshake(isn, 5000);

    struct Piece {
        std::uint32_t seq;
        std::string bytes;
    };
    std::vector<Piece> pieces;
    for (std::size_t off = 0; off < original.size();) {
        const std::size_t len = std::min<std::size_t>(1 + rng() % 1400, original.size() - off);
        pieces.push_back({isn + 1 + static_cast<std::uint32_t>(off), original.substr(off, len)});
        // Some retransmissions re-cut the data at different boundaries.
        if (rng() % 4 == 0 && off > 10) {
            const std::size_t back = rng() % 10;
            pieces.push_back({isn + 1 + static_cast<std::uint32_t>(off - back),
                              original.substr(off - back, len)});
        }
        off += len;
    }
    // Shuffle locally (a real network reorders within a window, not globally).
    for (std::size_t i = 0; i + 1 < pieces.size(); ++i) {
        const std::size_t j = i + rng() % std::min<std::size_t>(8, pieces.size() - i);
        std::swap(pieces[i], pieces[j]);
    }
    for (const Piece& p : pieces) feed(kClient, kServer, p.seq, ACK, p.bytes);

    EXPECT_EQ(rec().data[C2S].size(), original.size());
    EXPECT_EQ(rec().data[C2S], original);
    EXPECT_TRUE(rec().gaps[C2S].empty());
}
