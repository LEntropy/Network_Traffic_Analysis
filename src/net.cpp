#include "netaudit/net.hpp"

#include <cstdio>
#include <ctime>

namespace netaudit {

std::string ip_to_string(std::uint32_t ip) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (ip >> 24) & 0xFFu, (ip >> 16) & 0xFFu,
                  (ip >> 8) & 0xFFu, ip & 0xFFu);
    return buf;
}

std::string to_string(const Endpoint& ep) {
    return ip_to_string(ep.ip) + ":" + std::to_string(ep.port);
}

std::string format_timestamp(TimestampUs ts) {
    std::time_t secs = static_cast<std::time_t>(ts / 1000000);
    long micros = static_cast<long>(ts % 1000000);
    if (micros < 0) {
        micros += 1000000;
        --secs;
    }
    std::tm tm{};
    gmtime_r(&secs, &tm);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ", tm.tm_year + 1900,
                  tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, micros);
    return buf;
}

}  // namespace netaudit
