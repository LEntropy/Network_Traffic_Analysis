#include <atomic>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#include "netaudit/dispatcher.hpp"
#include "netaudit/http_parser.hpp"
#include "netaudit/log.hpp"
#include "netaudit/packet.hpp"
#include "netaudit/pcap_source.hpp"
#include "netaudit/reassembly.hpp"

namespace {

std::atomic<bool> g_stop{false};

void handle_signal(int) { g_stop.store(true); }

void usage(const char* argv0) {
    std::cerr << "usage: " << argv0 << " (-r FILE | -i IFACE) [options]\n"
              << "  -r FILE            read packets from a pcap/pcapng file\n"
              << "  -i IFACE           capture live from an interface (needs CAP_NET_RAW)\n"
              << "  -f FILTER          BPF filter, e.g. \"tcp port 80\"\n"
              << "  -o FILE            write JSON Lines events to FILE (default: stdout)\n"
              << "  --idle-timeout SEC close idle connections after SEC seconds (default 120)\n"
              << "  -h, --help         show this help\n";
}

struct DecodeCounters {
    std::uint64_t packets = 0;
    std::uint64_t tcp = 0;
    std::uint64_t truncated = 0;
    std::uint64_t non_tcp = 0;
    std::uint64_t fragments = 0;
    std::uint64_t malformed = 0;
};

}  // namespace

int main(int argc, char** argv) {
    using namespace netaudit;

    CaptureOptions capture;
    std::string output_path;
    ReassemblyConfig reassembly_config;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const auto value = [&]() -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "missing value for " << arg << "\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (arg == "-r") capture.file = value();
        else if (arg == "-i") capture.interface = value();
        else if (arg == "-f") capture.bpf = value();
        else if (arg == "-o") output_path = value();
        else if (arg == "--idle-timeout")
            reassembly_config.idle_timeout_us = std::stoll(value()) * 1000000;
        else if (arg == "-h" || arg == "--help") {
            usage(argv[0]);
            return 0;
        } else {
            std::cerr << "unknown option: " << arg << "\n";
            usage(argv[0]);
            return 2;
        }
    }
    if (capture.file.empty() == capture.interface.empty()) {
        usage(argv[0]);
        return 2;
    }

    std::ofstream file_out;
    if (!output_path.empty()) {
        file_out.open(output_path, std::ios::out | std::ios::app);
        if (!file_out) {
            std::cerr << "cannot open " << output_path << "\n";
            return 1;
        }
    }
    JsonLinesSink sink(output_path.empty() ? std::cout : file_out);

    std::string error;
    std::unique_ptr<PcapSource> source = PcapSource::open(capture, error);
    if (!source) {
        std::cerr << error << "\n";
        return 1;
    }
    const auto link = link_type_from_dlt(source->datalink());
    if (!link) {
        std::cerr << "unsupported link type " << source->datalink() << "\n";
        return 1;
    }

    ParserRegistry registry;
    registry.add(http_parser_factory());
    TcpReassembler reassembler(registry.handler_factory(sink), reassembly_config);

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    DecodeCounters counters;
    TimestampUs last_ts = 0;
    TimestampUs last_expiry = 0;
    constexpr TimestampUs kExpiryInterval = 1000000;

    const bool ok = source->run(
        [&](const RawPacket& pkt) {
            ++counters.packets;
            last_ts = pkt.ts;
            TcpSegment seg;
            switch (decode_frame(*link, pkt.data, pkt.caplen, pkt.ts, seg)) {
                case DecodeStatus::Ok:
                    ++counters.tcp;
                    reassembler.process(seg);
                    break;
                case DecodeStatus::Truncated: ++counters.truncated; break;
                case DecodeStatus::NotIpv4:
                case DecodeStatus::NotTcp: ++counters.non_tcp; break;
                case DecodeStatus::Fragment: ++counters.fragments; break;
                case DecodeStatus::Malformed: ++counters.malformed; break;
            }
            // Packet time, not wall-clock time, so offline files expire flows correctly.
            if (pkt.ts - last_expiry >= kExpiryInterval) {
                reassembler.expire_idle(pkt.ts);
                last_expiry = pkt.ts;
            }
        },
        g_stop);

    reassembler.close_all(last_ts);
    if (!ok) std::cerr << "capture error: " << source->error() << "\n";

    const ReassemblyStats& rs = reassembler.stats();
    const CaptureStats cs = source->stats();
    LogRecord summary("stats");
    summary.add_int("packets", static_cast<std::int64_t>(counters.packets))
        .add_int("tcp_segments", static_cast<std::int64_t>(counters.tcp))
        .add_int("truncated", static_cast<std::int64_t>(counters.truncated))
        .add_int("non_tcp", static_cast<std::int64_t>(counters.non_tcp))
        .add_int("ip_fragments", static_cast<std::int64_t>(counters.fragments))
        .add_int("malformed", static_cast<std::int64_t>(counters.malformed))
        .add_int("flows", static_cast<std::int64_t>(rs.flows_created))
        .add_int("flows_rejected", static_cast<std::int64_t>(rs.flows_rejected))
        .add_int("delivered_bytes", static_cast<std::int64_t>(rs.delivered_bytes))
        .add_int("retransmitted_bytes", static_cast<std::int64_t>(rs.retransmitted_bytes))
        .add_int("overlap_bytes", static_cast<std::int64_t>(rs.overlap_bytes))
        .add_int("out_of_order_segments", static_cast<std::int64_t>(rs.out_of_order_segments))
        .add_int("gap_events", static_cast<std::int64_t>(rs.gap_events))
        .add_int("gap_bytes", static_cast<std::int64_t>(rs.gap_bytes))
        .add_int("events", static_cast<std::int64_t>(sink.emitted()));
    if (cs.available) {
        summary.add_int("kernel_dropped", static_cast<std::int64_t>(cs.dropped))
            .add_int("if_dropped", static_cast<std::int64_t>(cs.if_dropped));
    }
    std::cerr << summary.to_json() << "\n";
    return ok ? 0 : 1;
}
