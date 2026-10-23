#include <gtest/gtest.h>

#include "netaudit/dispatcher.hpp"
#include "netaudit/http_parser.hpp"
#include "test_util.hpp"

using namespace netaudit;
using namespace netaudit::test;
using namespace netaudit::tcp_flags;

namespace {

const Endpoint kClient{ip(10, 0, 0, 2), 51000};
const Endpoint kServer{ip(10, 0, 0, 1), 8080};

class HttpTest : public ::testing::Test {
protected:
    HttpTest() : parser_(ConnectionInfo{kClient, kServer, 0, false}, sink_) {}

    void client(const std::string& s, TimestampUs ts = 0) { send(Direction::ClientToServer, s, ts); }
    void server(const std::string& s, TimestampUs ts = 0) { send(Direction::ServerToClient, s, ts); }

    void send(Direction d, const std::string& s, TimestampUs ts) {
        parser_.on_data(d, reinterpret_cast<const std::uint8_t*>(s.data()), s.size(), ts);
    }

    // Feeds one byte at a time: every state must survive arbitrary segment boundaries.
    void client_bytewise(const std::string& s) {
        for (char c : s) client(std::string(1, c));
    }
    void server_bytewise(const std::string& s) {
        for (char c : s) server(std::string(1, c));
    }

    const LogRecord& rec(std::size_t i = 0) { return sink_.records.at(i); }
    std::string str(std::size_t i, const char* key) {
        const std::string* v = rec(i).str(key);
        return v ? *v : "<missing>";
    }

    CollectingSink sink_;
    HttpParser parser_;
};

}  // namespace

TEST_F(HttpTest, SimpleExchange) {
    client("GET /index.html?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5\r\n\r\n",
           100);
    server("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello", 350);

    ASSERT_EQ(sink_.records.size(), 1u);
    EXPECT_EQ(str(0, "type"), "http");
    EXPECT_EQ(str(0, "method"), "GET");
    EXPECT_EQ(str(0, "host"), "example.com");
    EXPECT_EQ(str(0, "uri"), "/index.html?q=1");
    EXPECT_EQ(str(0, "user_agent"), "curl/8.5");
    EXPECT_EQ(rec().integer("status"), 200);
    EXPECT_EQ(str(0, "resp_content_type"), "text/html");
    EXPECT_EQ(rec().integer("resp_body_bytes"), 5);
    EXPECT_EQ(rec().integer("response_delay_us"), 250);
    EXPECT_EQ(rec().integer("server_port"), 8080);
    EXPECT_EQ(rec().str("flags"), nullptr);
}

TEST_F(HttpTest, ByteAtATime) {
    client_bytewise(
        "POST /api HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n"
        "Content-Length: 7\r\n\r\n{\"a\":1}");
    server_bytewise(
        "HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n"
        "4\r\nabcd\r\n3;ext=1\r\nefg\r\n0\r\nX-Trailer: t\r\n\r\n");

    ASSERT_EQ(sink_.records.size(), 1u);
    EXPECT_EQ(str(0, "method"), "POST");
    EXPECT_EQ(str(0, "req_content_type"), "application/json");
    EXPECT_EQ(rec().integer("req_body_bytes"), 7);
    EXPECT_EQ(rec().integer("status"), 201);
    EXPECT_EQ(rec().integer("resp_body_bytes"), 7);
}

TEST_F(HttpTest, PipelinedRequestsMatchResponsesInOrder) {
    client("GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n");
    server("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"
           "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nBB");

    ASSERT_EQ(sink_.records.size(), 2u);
    EXPECT_EQ(str(0, "uri"), "/a");
    EXPECT_EQ(rec(0).integer("status"), 200);
    EXPECT_EQ(str(1, "uri"), "/b");
    EXPECT_EQ(rec(1).integer("status"), 404);
    EXPECT_EQ(rec(1).integer("resp_body_bytes"), 2);
}

TEST_F(HttpTest, HeadResponseHasNoBody) {
    client("HEAD /big HTTP/1.1\r\nHost: h\r\n\r\nGET /next HTTP/1.1\r\nHost: h\r\n\r\n");
    // Content-Length on a HEAD response describes the GET body; no body follows.
    server("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"
           "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    ASSERT_EQ(sink_.records.size(), 2u);
    EXPECT_EQ(rec(0).integer("resp_body_bytes"), 0);
    EXPECT_EQ(str(1, "uri"), "/next");
    EXPECT_EQ(rec(1).integer("resp_body_bytes"), 2);
}

TEST_F(HttpTest, NotModifiedAndContinue) {
    client("GET /c HTTP/1.1\r\nHost: h\r\n\r\n");
    server("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 304 Not Modified\r\nETag: x\r\n\r\n");
    ASSERT_EQ(sink_.records.size(), 1u);
    EXPECT_EQ(rec().integer("status"), 304);
}

TEST_F(HttpTest, BodyDelimitedByClose) {
    client("GET /old HTTP/1.0\r\n\r\n");
    server("HTTP/1.0 200 OK\r\n\r\nsome body");
    server(" more");
    EXPECT_TRUE(sink_.records.empty());
    parser_.on_close(CloseReason::Fin, 0);
    ASSERT_EQ(sink_.records.size(), 1u);
    EXPECT_EQ(rec().integer("resp_body_bytes"), 14);
    EXPECT_EQ(rec().str("flags"), nullptr);
}

TEST_F(HttpTest, UnansweredRequestOnClose) {
    client("GET /x HTTP/1.1\r\nHost: h\r\n\r\n");
    parser_.on_close(CloseReason::Reset, 0);
    ASSERT_EQ(sink_.records.size(), 1u);
    EXPECT_EQ(rec().integer("status"), 0);
    EXPECT_EQ(str(0, "flags"), "no_response");
}

TEST_F(HttpTest, TruncatedResponseIsIncomplete) {
    client("GET /x HTTP/1.1\r\nHost: h\r\n\r\n");
    server("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly-part");
    parser_.on_close(CloseReason::Fin, 0);
    ASSERT_EQ(sink_.records.size(), 1u);
    EXPECT_EQ(rec().integer("status"), 200);
    EXPECT_EQ(rec().integer("resp_body_bytes"), 9);
    EXPECT_EQ(str(0, "flags"), "incomplete");
}

TEST_F(HttpTest, GapInsideBodyKeepsFraming) {
    client("GET /x HTTP/1.1\r\nHost: h\r\n\r\nGET /y HTTP/1.1\r\nHost: h\r\n\r\n");
    server("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc");
    parser_.on_gap(Direction::ServerToClient, 4, 0);
    server("hij");
    server("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    ASSERT_EQ(sink_.records.size(), 2u);
    EXPECT_EQ(rec(0).integer("resp_body_bytes"), 10);
    EXPECT_EQ(str(0, "flags"), "body_gap");
    EXPECT_EQ(str(1, "uri"), "/y");
}

TEST_F(HttpTest, GapInHeadersStopsParsing) {
    client("GET /x HTTP/1.1\r\nHo");
    parser_.on_gap(Direction::ClientToServer, 50, 0);
    // The request line was never completed, so there is nothing trustworthy to log.
    EXPECT_FALSE(parser_.wants_data());
    EXPECT_TRUE(sink_.records.empty());
}

TEST_F(HttpTest, GapAfterRequestIsReported) {
    client("GET /x HTTP/1.1\r\nHost: h\r\n\r\n");
    server("HTTP/1.1 2");
    parser_.on_gap(Direction::ServerToClient, 50, 0);
    ASSERT_EQ(sink_.records.size(), 1u);
    EXPECT_EQ(str(0, "uri"), "/x");
    EXPECT_EQ(str(0, "flags"), "gap,no_response");
}

TEST_F(HttpTest, SmugglingIndicatorsAreFlagged) {
    client("POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n"
           "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    server("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    ASSERT_EQ(sink_.records.size(), 1u);
    EXPECT_EQ(str(0, "flags"), "cl_te_conflict");
    EXPECT_EQ(rec().integer("req_body_bytes"), 0);  // chunked wins over Content-Length
}

TEST_F(HttpTest, ConflictingContentLengthStops) {
    client("POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n");
    EXPECT_FALSE(parser_.wants_data());
    ASSERT_EQ(sink_.records.size(), 1u);
    EXPECT_EQ(str(0, "flags"), "conflicting_content_length,no_response");
}

TEST_F(HttpTest, HeaderTooLarge) {
    client("GET / HTTP/1.1\r\nX-Big: " + std::string(70 * 1024, 'a'));
    EXPECT_FALSE(parser_.wants_data());
}

TEST_F(HttpTest, NonHttpStopsWithoutRecords) {
    client("GARBAGE\r\n\r\n");
    EXPECT_FALSE(parser_.wants_data());
    EXPECT_TRUE(sink_.records.empty());
}

TEST_F(HttpTest, WebSocketUpgradeStops) {
    client("GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
    server("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x05hello");
    ASSERT_EQ(sink_.records.size(), 1u);
    EXPECT_EQ(rec().integer("status"), 101);
    EXPECT_FALSE(parser_.wants_data());
}

// --- Plug-in dispatch through the reassembler -------------------------------------------

namespace {

class PipelineTest : public ::testing::Test {
protected:
    PipelineTest() {
        registry_.add(http_parser_factory());
        reassembler_ = std::make_unique<TcpReassembler>(registry_.handler_factory(sink_));
    }

    void feed(Endpoint src, Endpoint dst, std::uint32_t seq, std::uint8_t flags,
              const std::string& payload = "") {
        // Goes through the real frame decoder as well.
        auto frame = make_frame(src, dst, seq, 0, flags, payload);
        TcpSegment seg;
        ASSERT_EQ(decode_frame(LinkType::Ethernet, frame.data(), frame.size(), 0, seg),
                  DecodeStatus::Ok);
        reassembler_->process(seg);
    }

    CollectingSink sink_;
    ParserRegistry registry_;
    std::unique_ptr<TcpReassembler> reassembler_;
};

}  // namespace

TEST_F(PipelineTest, HttpOnNonStandardPortIsDetectedByContent) {
    const Endpoint c{ip(10, 0, 0, 2), 40000};
    const Endpoint s{ip(10, 0, 0, 1), 9999};
    feed(c, s, 100, SYN);
    feed(s, c, 700, SYN | ACK);
    // Request split mid-method and delivered out of order.
    feed(c, s, 103, ACK, "T /p HTTP/1.1\r\nHost: x\r\n\r\n");
    feed(c, s, 101, ACK, "GE");
    feed(s, c, 701, ACK, "HTTP/1.1 204 No Content\r\n\r\n");
    feed(c, s, 129, ACK | FIN);
    feed(s, c, 728, ACK | FIN);

    ASSERT_EQ(sink_.records.size(), 1u);
    EXPECT_EQ(*sink_.records[0].str("uri"), "/p");
    EXPECT_EQ(sink_.records[0].integer("status"), 204);
    EXPECT_EQ(reassembler_->active_flows(), 0u);
}

TEST_F(PipelineTest, ServerFirstProtocolIsIgnored) {
    const Endpoint c{ip(10, 0, 0, 2), 40001};
    const Endpoint s{ip(10, 0, 0, 1), 22};
    feed(c, s, 100, SYN);
    feed(s, c, 700, SYN | ACK);
    feed(s, c, 701, ACK, "SSH-2.0-OpenSSH_9.6\r\n");
    feed(c, s, 101, ACK, "GET / HTTP/1.1\r\n\r\n");  // too late: flow already classified
    reassembler_->close_all(0);
    EXPECT_TRUE(sink_.records.empty());
}
