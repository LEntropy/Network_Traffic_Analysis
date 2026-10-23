#include <gtest/gtest.h>

#include "netaudit/log.hpp"
#include "netaudit/net.hpp"

using namespace netaudit;

TEST(Json, EscapesControlAndQuotes) {
    LogRecord r("t");
    r.add_str("s", "a\"b\\c\n\x01").add_int("n", -5).add_bool("b", true);
    EXPECT_EQ(r.to_json(), R"({"type":"t","s":"a\"b\\c\n\u0001","n":-5,"b":true})");
}

TEST(Json, KeepsValidUtf8AndReplacesInvalidBytes) {
    LogRecord r("t");
    r.add_str("ko", "\xEC\x95\x88\xEB\x85\x95");        // valid Korean text
    r.add_str("bad", "a\xFF" "b\xC0\xAF" "c\xED\xA0\x80");  // invalid, overlong, surrogate
    const std::string json = r.to_json();
    EXPECT_NE(json.find("\"ko\":\"\xEC\x95\x88\xEB\x85\x95\""), std::string::npos);
    EXPECT_EQ(json.find('\xFF'), std::string::npos);
    EXPECT_EQ(json.find('\xC0'), std::string::npos);
    EXPECT_EQ(json.find('\xA0'), std::string::npos);
}

TEST(Format, Timestamp) {
    EXPECT_EQ(format_timestamp(1761206400123456LL), "2025-10-23T08:00:00.123456Z");
    EXPECT_EQ(ip_to_string(0x0A000001u), "10.0.0.1");
}
