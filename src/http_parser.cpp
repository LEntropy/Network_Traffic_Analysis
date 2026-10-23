#include "netaudit/http_parser.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <functional>
#include <memory>

namespace netaudit {

namespace {

constexpr std::size_t kMaxLineBytes = 4096;  // chunk-size and trailer lines

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim_ows(const std::string& s) {
    const auto is_ows = [](char c) { return c == ' ' || c == '\t'; };
    std::size_t b = 0;
    std::size_t e = s.size();
    while (b < e && is_ows(s[b])) ++b;
    while (e > b && is_ows(s[e - 1])) --e;
    return s.substr(b, e - b);
}

bool is_token(const std::string& s) {
    if (s.empty()) return false;
    for (unsigned char c : s) {
        if (c <= 0x20 || c >= 0x7F) return false;
        if (std::string("\"(),/:;<=>?@[\\]{}").find(static_cast<char>(c)) != std::string::npos) {
            return false;
        }
    }
    return true;
}

bool parse_decimal(const std::string& s, std::uint64_t& out) {
    if (s.empty() || s.size() > 19) return false;
    std::uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<std::uint64_t>(c - '0');
    }
    out = v;
    return true;
}

bool parse_hex(const std::string& s, std::uint64_t& out) {
    if (s.empty() || s.size() > 15) return false;
    std::uint64_t v = 0;
    for (char c : s) {
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        v = (v << 4) | static_cast<std::uint64_t>(d);
    }
    out = v;
    return true;
}

std::vector<std::string> split_lines(const std::string& head) {
    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start <= head.size()) {
        std::size_t nl = head.find('\n', start);
        std::string line = head.substr(start, nl == std::string::npos ? std::string::npos
                                                                      : nl - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(std::move(line));
        if (nl == std::string::npos) break;
        start = nl + 1;
    }
    return lines;
}

std::string clip(const std::string& s, std::size_t max) {
    return s.size() <= max ? s : s.substr(0, max);
}

}  // namespace

const std::string* HttpParser::Message::header(const std::string& lower_name) const {
    for (const auto& [name, value] : headers) {
        if (name == lower_name) return &value;
    }
    return nullptr;
}

HttpParser::HttpParser(const ConnectionInfo& info, EventSink& sink, HttpParserConfig config)
    : info_(info), sink_(sink), config_(config) {}

void HttpParser::on_data(Direction dir, const std::uint8_t* data, std::size_t len,
                         TimestampUs ts) {
    if (stopped_) return;
    feed(dir, reinterpret_cast<const char*>(data), len, ts);
}

void HttpParser::feed(Direction dir, const char* p, std::size_t n, TimestampUs ts) {
    Half& h = half_[index_of(dir)];
    std::size_t i = 0;
    while (i < n && !stopped_) {
        if (h.in_message) h.msg.ts_end = ts;
        switch (h.state) {
            case State::Head:
                i += feed_head(dir, p + i, n - i, ts);
                break;

            case State::BodyLength:
            case State::ChunkData: {
                const std::size_t take = static_cast<std::size_t>(
                    std::min<std::uint64_t>(h.remaining, n - i));
                h.msg.body_bytes += take;
                h.remaining -= take;
                i += take;
                if (h.remaining == 0) {
                    if (h.state == State::BodyLength) finish_message(dir, ts);
                    else h.state = State::ChunkDataEnd;
                }
                break;
            }

            case State::ChunkDataEnd:
            case State::ChunkSize:
            case State::ChunkTrailer: {
                std::string line;
                bool complete = false;
                i += feed_line(h, p + i, n - i, line, complete);
                if (!complete) {
                    if (h.buf.size() > kMaxLineBytes) stop(dir, "line_too_long");
                    break;
                }
                if (h.state == State::ChunkDataEnd) {
                    if (!line.empty()) stop(dir, "bad_chunk");
                    else h.state = State::ChunkSize;
                } else if (h.state == State::ChunkSize) {
                    const std::string size_str = trim_ows(line.substr(0, line.find(';')));
                    std::uint64_t size = 0;
                    if (!parse_hex(size_str, size)) {
                        stop(dir, "bad_chunk");
                    } else if (size == 0) {
                        h.state = State::ChunkTrailer;
                    } else {
                        h.remaining = size;
                        h.state = State::ChunkData;
                    }
                } else if (line.empty()) {
                    finish_message(dir, ts);  // end of trailer section
                }
                break;
            }

            case State::BodyUntilClose:
                h.msg.body_bytes += n - i;
                i = n;
                break;
        }
    }
}

std::size_t HttpParser::feed_line(Half& h, const char* p, std::size_t n, std::string& line,
                                  bool& complete) {
    const char* nl = static_cast<const char*>(std::memchr(p, '\n', n));
    if (nl == nullptr) {
        h.buf.append(p, n);
        complete = false;
        return n;
    }
    const std::size_t used = static_cast<std::size_t>(nl - p) + 1;
    h.buf.append(p, used - 1);
    if (!h.buf.empty() && h.buf.back() == '\r') h.buf.pop_back();
    line = std::move(h.buf);
    h.buf.clear();
    complete = true;
    return used;
}

std::size_t HttpParser::feed_head(Direction dir, const char* p, std::size_t n, TimestampUs ts) {
    Half& h = half_[index_of(dir)];
    std::size_t i = 0;
    if (!h.in_message) {
        // RFC 9112 2.2: ignore empty lines received before a start line.
        while (i < n && (p[i] == '\r' || p[i] == '\n')) ++i;
        if (i == n) return n;
        h.in_message = true;
        h.msg = Message{};
        h.msg.ts_start = ts;
        h.msg.ts_end = ts;
    }

    const std::size_t old_size = h.buf.size();
    h.buf.append(p + i, n - i);
    const std::size_t from = old_size >= 3 ? old_size - 3 : 0;
    const std::size_t crlf = h.buf.find("\r\n\r\n", from);
    const std::size_t lf = h.buf.find("\n\n", from);

    std::size_t end = std::string::npos;
    std::size_t term = 0;
    if (crlf != std::string::npos && (lf == std::string::npos || crlf < lf)) {
        end = crlf;
        term = 4;
    } else if (lf != std::string::npos) {
        end = lf;
        term = 2;
        h.msg.anomalies.push_back("bare_lf");
    }

    if (end == std::string::npos || end > config_.max_header_bytes) {
        if (h.buf.size() > config_.max_header_bytes) stop(dir, "header_too_large");
        return n;
    }

    // The terminator ends inside the bytes just appended, so everything after it came
    // from `p` and is handed back to feed() as body bytes.
    const std::size_t leftover = h.buf.size() - (end + term);
    const std::string head = h.buf.substr(0, end);
    h.buf.clear();

    if (parse_head(dir, head)) start_body(dir, ts);
    return n - leftover;
}

bool HttpParser::parse_head(Direction dir, const std::string& head) {
    Message& m = half_[index_of(dir)].msg;
    const std::vector<std::string> lines = split_lines(head);
    const std::string& start = lines.front();

    if (dir == Direction::ClientToServer) {
        const std::size_t sp1 = start.find(' ');
        const std::size_t sp2 = sp1 == std::string::npos ? sp1 : start.find(' ', sp1 + 1);
        if (sp2 == std::string::npos) {
            stop(dir, "not_http");
            return false;
        }
        m.method = start.substr(0, sp1);
        m.target = start.substr(sp1 + 1, sp2 - sp1 - 1);
        const std::string version = start.substr(sp2 + 1);
        if (!is_token(m.method) || m.target.empty() || version.rfind("HTTP/1.", 0) != 0) {
            stop(dir, "not_http");
            return false;
        }
    } else {
        // HTTP/1.1 200 OK
        if (start.size() < 12 || start.rfind("HTTP/1.", 0) != 0 || start[8] != ' ' ||
            !std::isdigit(static_cast<unsigned char>(start[9])) ||
            !std::isdigit(static_cast<unsigned char>(start[10])) ||
            !std::isdigit(static_cast<unsigned char>(start[11]))) {
            stop(dir, "not_http");
            return false;
        }
        m.status = std::stoi(start.substr(9, 3));
    }

    for (std::size_t k = 1; k < lines.size(); ++k) {
        const std::string& line = lines[k];
        if (line.empty()) continue;
        if (line[0] == ' ' || line[0] == '\t') {
            // Obsolete line folding: a continuation of the previous header value.
            m.anomalies.push_back("obs_fold");
            if (!m.headers.empty()) m.headers.back().second += " " + trim_ows(line);
            continue;
        }
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos) {
            m.anomalies.push_back("bad_header_line");
            continue;
        }
        std::string name = line.substr(0, colon);
        if (!is_token(name)) {
            // e.g. "Content-Length : 5" - servers disagree on this, a classic smuggling vector
            m.anomalies.push_back("bad_header_name");
            name = trim_ows(name);
        }
        m.headers.emplace_back(to_lower(name), trim_ows(line.substr(colon + 1)));
    }
    return true;
}

void HttpParser::start_body(Direction dir, TimestampUs ts) {
    Half& h = half_[index_of(dir)];
    Message& m = h.msg;

    if (dir == Direction::ServerToClient) {
        const Message* req = pending_.empty() ? nullptr : &pending_.front();
        if (m.status >= 100 && m.status < 200) {
            if (m.status == 101) {
                // Switched to another protocol (e.g. WebSocket); nothing more to parse.
                finish_message(dir, ts);
                stopped_ = true;
                return;
            }
            // Interim response (100 Continue); the final response follows.
            h = Half{};
            return;
        }
        const bool head_request = req != nullptr && req->method == "HEAD";
        if (head_request || m.status == 204 || m.status == 304) {
            finish_message(dir, ts);
            return;
        }
        if (req != nullptr && req->method == "CONNECT" && m.status >= 200 && m.status < 300) {
            finish_message(dir, ts);
            stopped_ = true;  // the connection is now an opaque tunnel
            return;
        }
    }

    const std::string* te = m.header("transfer-encoding");
    std::vector<std::string> lengths;
    for (const auto& [name, value] : m.headers) {
        if (name == "content-length") lengths.push_back(value);
    }

    if (te != nullptr && !lengths.empty()) m.anomalies.push_back("cl_te_conflict");
    if (std::adjacent_find(lengths.begin(), lengths.end(), std::not_equal_to<>()) !=
        lengths.end()) {
        stop(dir, "conflicting_content_length");
        return;
    }

    if (te != nullptr) {
        const std::string codings = to_lower(*te);
        const std::size_t comma = codings.rfind(',');
        const std::string last =
            trim_ows(comma == std::string::npos ? codings : codings.substr(comma + 1));
        if (last == "chunked") {
            h.state = State::ChunkSize;
        } else if (dir == Direction::ServerToClient) {
            h.state = State::BodyUntilClose;
        } else {
            stop(dir, "unsupported_transfer_encoding");
        }
        return;
    }

    if (!lengths.empty()) {
        std::uint64_t length = 0;
        if (!parse_decimal(lengths.front(), length)) {
            stop(dir, "bad_content_length");
            return;
        }
        if (length == 0) {
            finish_message(dir, ts);
        } else {
            h.remaining = length;
            h.state = State::BodyLength;
        }
        return;
    }

    if (dir == Direction::ClientToServer) {
        finish_message(dir, ts);  // requests without framing headers have no body
    } else {
        h.state = State::BodyUntilClose;
    }
}

void HttpParser::finish_message(Direction dir, TimestampUs ts) {
    Half& h = half_[index_of(dir)];
    Message m = std::move(h.msg);
    m.ts_end = ts;
    h = Half{};

    if (dir == Direction::ClientToServer) {
        if (pending_.size() >= config_.max_pending_requests) {
            emit(&pending_.front(), nullptr, "unanswered");
            pending_.pop_front();
        }
        pending_.push_back(std::move(m));
        return;
    }

    if (pending_.empty()) {
        emit(nullptr, &m, "orphan_response");
        return;
    }
    emit(&pending_.front(), &m, "");
    pending_.pop_front();
}

void HttpParser::emit(const Message* request, const Message* response,
                      const std::string& extra_flag) {
    const Message& first = request != nullptr ? *request : *response;
    LogRecord r("http");
    r.add_str("ts", format_timestamp(first.ts_start))
        .add_str("client_ip", ip_to_string(info_.client.ip))
        .add_int("client_port", info_.client.port)
        .add_str("server_ip", ip_to_string(info_.server.ip))
        .add_int("server_port", info_.server.port);

    const auto header_or_empty = [&](const Message& m, const char* name) {
        const std::string* v = m.header(name);
        return v != nullptr ? clip(*v, config_.max_field_bytes) : std::string();
    };

    if (request != nullptr) {
        r.add_str("method", request->method)
            .add_str("host", header_or_empty(*request, "host"))
            .add_str("uri", clip(request->target, config_.max_field_bytes))
            .add_str("user_agent", header_or_empty(*request, "user-agent"))
            .add_str("req_content_type", header_or_empty(*request, "content-type"))
            .add_int("req_body_bytes", static_cast<std::int64_t>(request->body_bytes));
    }
    if (response != nullptr) {
        r.add_int("status", response->status)
            .add_str("resp_content_type", header_or_empty(*response, "content-type"))
            .add_int("resp_body_bytes", static_cast<std::int64_t>(response->body_bytes));
        if (request != nullptr) {
            r.add_int("response_delay_us", response->ts_start - request->ts_end);
        }
    } else {
        r.add_int("status", 0);
    }

    std::vector<std::string> flags;
    for (const Message* m : {request, response}) {
        if (m != nullptr) flags.insert(flags.end(), m->anomalies.begin(), m->anomalies.end());
    }
    if (!extra_flag.empty()) flags.push_back(extra_flag);
    if (info_.midstream) flags.push_back("midstream");
    std::sort(flags.begin(), flags.end());
    flags.erase(std::unique(flags.begin(), flags.end()), flags.end());
    std::string joined;
    for (const std::string& f : flags) {
        if (!joined.empty()) joined += ',';
        joined += f;
    }
    if (!joined.empty()) r.add_str("flags", joined);

    sink_.emit(r);
}

void HttpParser::stop(Direction dir, const std::string& reason) {
    if (stopped_) return;
    stopped_ = true;

    // Record the message that triggered the stop, then flush everything still open.
    Half& c = half_[index_of(Direction::ClientToServer)];
    Half& s = half_[index_of(Direction::ServerToClient)];
    half_[index_of(dir)].msg.anomalies.push_back(reason);

    if (c.in_message && !c.msg.method.empty()) pending_.push_back(std::move(c.msg));
    if (s.in_message && s.msg.status != 0) {
        if (pending_.empty()) {
            emit(nullptr, &s.msg, "orphan_response");
        } else {
            emit(&pending_.front(), &s.msg, "");
            pending_.pop_front();
        }
    } else if (dir == Direction::ServerToClient && !pending_.empty()) {
        pending_.front().anomalies.push_back(reason);
    }
    while (!pending_.empty()) {
        emit(&pending_.front(), nullptr, "no_response");
        pending_.pop_front();
    }
    c = Half{};
    s = Half{};
}

void HttpParser::on_gap(Direction dir, std::uint64_t bytes, TimestampUs ts) {
    if (stopped_) return;
    Half& h = half_[index_of(dir)];

    // A hole inside a body of known size only costs us body bytes; framing survives.
    if ((h.state == State::BodyLength || h.state == State::ChunkData) &&
        bytes <= h.remaining) {
        h.msg.anomalies.push_back("body_gap");
        h.msg.body_bytes += bytes;
        h.remaining -= bytes;
        if (h.remaining == 0) {
            if (h.state == State::BodyLength) finish_message(dir, ts);
            else h.state = State::ChunkDataEnd;
        }
        return;
    }
    if (h.state == State::BodyUntilClose) {
        h.msg.anomalies.push_back("body_gap");
        h.msg.body_bytes += bytes;
        return;
    }
    stop(dir, "gap");
}

void HttpParser::on_close(CloseReason, TimestampUs ts) {
    if (stopped_) return;
    Half& s = half_[index_of(Direction::ServerToClient)];
    if (s.in_message && s.state == State::BodyUntilClose) {
        finish_message(Direction::ServerToClient, ts);  // close delimits this body
    }
    const Half& c = half_[index_of(Direction::ClientToServer)];
    const bool partial = (c.in_message && !c.msg.method.empty()) ||
                         (s.in_message && s.msg.status != 0);
    if (partial) {
        const Direction dir = s.in_message ? Direction::ServerToClient
                                           : Direction::ClientToServer;
        stop(dir, "incomplete");
        return;
    }
    stopped_ = true;
    while (!pending_.empty()) {
        emit(&pending_.front(), nullptr, "no_response");
        pending_.pop_front();
    }
}

ParserFactory http_parser_factory(HttpParserConfig config) {
    ParserFactory f;
    f.name = "http";
    f.probe = [](const ProbeInput& in) {
        static const char* const kMethods[] = {"GET ",     "POST ",    "PUT ",
                                               "DELETE ",  "HEAD ",    "OPTIONS ",
                                               "PATCH ",   "CONNECT ", "TRACE "};
        if (in.client.empty()) {
            // Protocols where the server speaks first (SMTP, MySQL, SSH) are not HTTP.
            return in.server.empty() ? ProbeResult::NeedMore : ProbeResult::NoMatch;
        }
        bool prefix = false;
        for (const char* m : kMethods) {
            const std::string token(m);
            if (in.client.size() >= token.size()) {
                if (in.client.compare(0, token.size(), token) == 0) return ProbeResult::Match;
            } else if (token.compare(0, in.client.size(), in.client) == 0) {
                prefix = true;
            }
        }
        return prefix ? ProbeResult::NeedMore : ProbeResult::NoMatch;
    };
    f.create = [config](const ConnectionInfo& info, EventSink& sink) {
        return std::unique_ptr<StreamHandler>(new HttpParser(info, sink, config));
    };
    return f;
}

}  // namespace netaudit
