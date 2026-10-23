#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <utility>
#include <vector>

#include "netaudit/dispatcher.hpp"
#include "netaudit/log.hpp"
#include "netaudit/reassembly.hpp"

namespace netaudit {

struct HttpParserConfig {
    std::size_t max_header_bytes = 64 * 1024;
    std::size_t max_pending_requests = 64;  // pipelined requests awaiting a response
    std::size_t max_field_bytes = 2048;     // longer URIs / header values are cut in the log
};

// Incremental HTTP/1.x parser for one TCP connection. Emits one "http" record per
// request/response exchange, matching pipelined responses to requests in order.
//
// Body framing follows RFC 9112 section 6: Transfer-Encoding: chunked wins over
// Content-Length, responses to HEAD and 1xx/204/304 have no body, and a response with
// neither header is read until the connection closes.
class HttpParser : public StreamHandler {
public:
    HttpParser(const ConnectionInfo& info, EventSink& sink, HttpParserConfig config = {});

    void on_data(Direction dir, const std::uint8_t* data, std::size_t len,
                 TimestampUs ts) override;
    void on_gap(Direction dir, std::uint64_t bytes, TimestampUs ts) override;
    void on_close(CloseReason reason, TimestampUs ts) override;
    bool wants_data() const override { return !stopped_; }

private:
    enum class State {
        Head,
        BodyLength,
        ChunkSize,
        ChunkData,
        ChunkDataEnd,
        ChunkTrailer,
        BodyUntilClose,
    };

    struct Message {
        TimestampUs ts_start = 0;
        TimestampUs ts_end = 0;
        std::string method;  // request
        std::string target;  // request
        int status = 0;      // response
        std::vector<std::pair<std::string, std::string>> headers;  // names lowercased
        std::uint64_t body_bytes = 0;
        std::vector<std::string> anomalies;

        const std::string* header(const std::string& lower_name) const;
    };

    struct Half {
        State state = State::Head;
        std::string buf;  // partial head, chunk-size line or trailer line
        std::uint64_t remaining = 0;
        bool in_message = false;
        Message msg;
    };

    void feed(Direction dir, const char* p, std::size_t n, TimestampUs ts);
    std::size_t feed_head(Direction dir, const char* p, std::size_t n, TimestampUs ts);
    std::size_t feed_line(Half& h, const char* p, std::size_t n, std::string& line,
                          bool& complete);
    bool parse_head(Direction dir, const std::string& head);
    void start_body(Direction dir, TimestampUs ts);
    void finish_message(Direction dir, TimestampUs ts);
    void emit(const Message* request, const Message* response, const std::string& extra_flag);
    void stop(Direction dir, const std::string& reason);

    ConnectionInfo info_;
    EventSink& sink_;
    HttpParserConfig config_;
    Half half_[2];
    std::deque<Message> pending_;
    bool stopped_ = false;
};

// Plug-in registration for ParserRegistry. The probe matches a client stream that starts
// with an HTTP/1.x request line.
ParserFactory http_parser_factory(HttpParserConfig config = {});

}  // namespace netaudit
