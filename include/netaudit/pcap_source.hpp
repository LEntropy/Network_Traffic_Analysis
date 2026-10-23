#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "netaudit/net.hpp"

struct pcap;

namespace netaudit {

struct CaptureOptions {
    std::string file;       // read a capture file, or
    std::string interface;  // capture live from an interface
    std::string bpf;        // optional BPF filter, e.g. "tcp port 80"
    int snaplen = 65535;
    bool promiscuous = true;
};

struct RawPacket {
    const std::uint8_t* data;
    std::size_t caplen;
    std::size_t wirelen;
    TimestampUs ts;
};

struct CaptureStats {
    bool available = false;  // only live captures report kernel counters
    std::uint64_t received = 0;
    std::uint64_t dropped = 0;
    std::uint64_t if_dropped = 0;
};

// Thin RAII wrapper over libpcap for both offline files and live interfaces.
class PcapSource {
public:
    static std::unique_ptr<PcapSource> open(const CaptureOptions& options, std::string& error);
    ~PcapSource();

    PcapSource(const PcapSource&) = delete;
    PcapSource& operator=(const PcapSource&) = delete;

    int datalink() const;

    // Calls `on_packet` for every packet until the file ends, `stop` becomes true, or an
    // error occurs. Returns false on error (see error()).
    bool run(const std::function<void(const RawPacket&)>& on_packet,
             const std::atomic<bool>& stop);

    CaptureStats stats() const;
    const std::string& error() const { return error_; }

private:
    PcapSource(pcap* handle, bool live) : handle_(handle), live_(live) {}

    pcap* handle_;
    bool live_;
    std::string error_;
};

}  // namespace netaudit
