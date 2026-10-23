#pragma once

#include <cstdint>
#include <mutex>
#include <ostream>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace netaudit {

// One audit event: an ordered list of fields serialized as a single JSON object.
class LogRecord {
public:
    using Value = std::variant<std::string, std::int64_t, bool>;

    explicit LogRecord(std::string type) { add_str("type", std::move(type)); }

    // Separate names on purpose: a std::variant<std::string, ..., bool> would silently
    // turn a string literal into `true`.
    LogRecord& add_str(std::string key, std::string value) {
        fields_.emplace_back(std::move(key), Value{std::move(value)});
        return *this;
    }
    LogRecord& add_int(std::string key, std::int64_t value) {
        fields_.emplace_back(std::move(key), Value{value});
        return *this;
    }
    LogRecord& add_bool(std::string key, bool value) {
        fields_.emplace_back(std::move(key), Value{value});
        return *this;
    }

    const std::vector<std::pair<std::string, Value>>& fields() const { return fields_; }

    // Returns the string field `key`, or nullptr.
    const std::string* str(const std::string& key) const;
    // Returns the integer field `key`, or `fallback`.
    std::int64_t integer(const std::string& key, std::int64_t fallback = -1) const;

    std::string to_json() const;

private:
    std::vector<std::pair<std::string, Value>> fields_;
};

// Appends `s` as a JSON string literal. Invalid UTF-8 bytes become U+FFFD so that
// arbitrary captured bytes can never produce invalid JSON.
void append_json_string(std::string& out, const std::string& s);

class EventSink {
public:
    virtual ~EventSink() = default;
    virtual void emit(const LogRecord& record) = 0;
};

// Writes one JSON object per line (JSON Lines).
class JsonLinesSink : public EventSink {
public:
    explicit JsonLinesSink(std::ostream& out) : out_(out) {}
    void emit(const LogRecord& record) override;
    std::uint64_t emitted() const { return emitted_; }

private:
    std::ostream& out_;
    std::mutex mu_;
    std::uint64_t emitted_ = 0;
};

}  // namespace netaudit
