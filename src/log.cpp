#include "netaudit/log.hpp"

#include <cstdio>

namespace netaudit {

namespace {

// Length of the valid UTF-8 sequence starting at s[i], or 0 if it is invalid.
std::size_t utf8_sequence_length(const std::string& s, std::size_t i) {
    const auto b = [&](std::size_t k) { return static_cast<unsigned char>(s[k]); };
    const unsigned char c = b(i);
    std::size_t n = 0;
    std::uint32_t cp = 0;
    if (c >= 0xC2 && c <= 0xDF) {
        n = 2;
        cp = c & 0x1Fu;
    } else if (c >= 0xE0 && c <= 0xEF) {
        n = 3;
        cp = c & 0x0Fu;
    } else if (c >= 0xF0 && c <= 0xF4) {
        n = 4;
        cp = c & 0x07u;
    } else {
        return 0;
    }
    if (i + n > s.size()) return 0;
    for (std::size_t k = 1; k < n; ++k) {
        if ((b(i + k) & 0xC0u) != 0x80u) return 0;
        cp = (cp << 6) | (b(i + k) & 0x3Fu);
    }
    // Reject overlong encodings, UTF-16 surrogates and values past U+10FFFF.
    if ((n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000) || cp > 0x10FFFF ||
        (cp >= 0xD800 && cp <= 0xDFFF)) {
        return 0;
    }
    return n;
}

}  // namespace

void append_json_string(std::string& out, const std::string& s) {
    out.push_back('"');
    for (std::size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c >= 0x80) {
            const std::size_t n = utf8_sequence_length(s, i);
            if (n == 0) {
                out += "\xEF\xBF\xBD";  // U+FFFD
                ++i;
            } else {
                out.append(s, i, n);
                i += n;
            }
            continue;
        }
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20 || c == 0x7F) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
        ++i;
    }
    out.push_back('"');
}

const std::string* LogRecord::str(const std::string& key) const {
    for (const auto& [k, v] : fields_) {
        if (k == key) return std::get_if<std::string>(&v);
    }
    return nullptr;
}

std::int64_t LogRecord::integer(const std::string& key, std::int64_t fallback) const {
    for (const auto& [k, v] : fields_) {
        if (k == key) {
            if (const auto* p = std::get_if<std::int64_t>(&v)) return *p;
            return fallback;
        }
    }
    return fallback;
}

std::string LogRecord::to_json() const {
    std::string out;
    out.reserve(256);
    out.push_back('{');
    bool first = true;
    for (const auto& [key, value] : fields_) {
        if (!first) out.push_back(',');
        first = false;
        append_json_string(out, key);
        out.push_back(':');
        if (const auto* s = std::get_if<std::string>(&value)) {
            append_json_string(out, *s);
        } else if (const auto* i = std::get_if<std::int64_t>(&value)) {
            out += std::to_string(*i);
        } else {
            out += std::get<bool>(value) ? "true" : "false";
        }
    }
    out.push_back('}');
    return out;
}

void JsonLinesSink::emit(const LogRecord& record) {
    const std::string line = record.to_json();
    std::lock_guard<std::mutex> lock(mu_);
    out_ << line << '\n';
    out_.flush();
    ++emitted_;
}

}  // namespace netaudit
