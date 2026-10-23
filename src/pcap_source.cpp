#include "netaudit/pcap_source.hpp"

#include <pcap/pcap.h>

namespace netaudit {

namespace {

bool apply_filter(pcap_t* p, const std::string& expr, std::string& error) {
    if (expr.empty()) return true;
    bpf_program prog{};
    if (pcap_compile(p, &prog, expr.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
        error = std::string("invalid BPF filter: ") + pcap_geterr(p);
        return false;
    }
    const int rc = pcap_setfilter(p, &prog);
    pcap_freecode(&prog);
    if (rc != 0) {
        error = std::string("cannot set BPF filter: ") + pcap_geterr(p);
        return false;
    }
    return true;
}

}  // namespace

std::unique_ptr<PcapSource> PcapSource::open(const CaptureOptions& options, std::string& error) {
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t* p = nullptr;
    const bool live = options.file.empty();

    if (!live) {
        // Normalise nanosecond-resolution files to microseconds.
        p = pcap_open_offline_with_tstamp_precision(options.file.c_str(),
                                                    PCAP_TSTAMP_PRECISION_MICRO, errbuf);
        if (p == nullptr) {
            error = errbuf;
            return nullptr;
        }
    } else {
        p = pcap_create(options.interface.c_str(), errbuf);
        if (p == nullptr) {
            error = errbuf;
            return nullptr;
        }
        pcap_set_snaplen(p, options.snaplen);
        pcap_set_promisc(p, options.promiscuous ? 1 : 0);
        pcap_set_timeout(p, 100);  // ms; lets run() notice `stop` on an idle link
        pcap_set_buffer_size(p, 16 << 20);
        const int rc = pcap_activate(p);
        if (rc < 0) {
            error = std::string("cannot capture on ") + options.interface + ": " +
                    pcap_statustostr(rc) + " " + pcap_geterr(p);
            pcap_close(p);
            return nullptr;
        }
    }

    if (!apply_filter(p, options.bpf, error)) {
        pcap_close(p);
        return nullptr;
    }
    return std::unique_ptr<PcapSource>(new PcapSource(p, live));
}

PcapSource::~PcapSource() {
    if (handle_ != nullptr) pcap_close(handle_);
}

int PcapSource::datalink() const { return pcap_datalink(handle_); }

bool PcapSource::run(const std::function<void(const RawPacket&)>& on_packet,
                     const std::atomic<bool>& stop) {
    while (!stop.load(std::memory_order_relaxed)) {
        pcap_pkthdr* hdr = nullptr;
        const u_char* data = nullptr;
        const int rc = pcap_next_ex(handle_, &hdr, &data);
        if (rc == 1) {
            const TimestampUs ts =
                static_cast<TimestampUs>(hdr->ts.tv_sec) * 1000000 + hdr->ts.tv_usec;
            on_packet(RawPacket{data, hdr->caplen, hdr->len, ts});
        } else if (rc == 0) {
            continue;  // live capture timeout with no packets
        } else if (rc == PCAP_ERROR_BREAK) {
            return true;  // end of capture file
        } else {
            error_ = pcap_geterr(handle_);
            return false;
        }
    }
    return true;
}

CaptureStats PcapSource::stats() const {
    CaptureStats s;
    pcap_stat ps{};
    if (live_ && pcap_stats(handle_, &ps) == 0) {
        s.available = true;
        s.received = ps.ps_recv;
        s.dropped = ps.ps_drop;
        s.if_dropped = ps.ps_ifdrop;
    }
    return s;
}

}  // namespace netaudit
