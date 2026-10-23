#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "netaudit/log.hpp"
#include "netaudit/reassembly.hpp"

namespace netaudit {

// The first bytes seen in each direction, used to recognise the protocol of a connection
// independently of its port numbers.
struct ProbeInput {
    const std::string& client;
    const std::string& server;
};

enum class ProbeResult { Match, NoMatch, NeedMore };

// A protocol parser plug-in. New protocols are added by registering another factory;
// nothing else in the pipeline changes.
struct ParserFactory {
    std::string name;
    std::function<ProbeResult(const ProbeInput&)> probe;
    std::function<std::unique_ptr<StreamHandler>(const ConnectionInfo&, EventSink&)> create;
};

struct DispatcherConfig {
    // Give up on recognising a connection after this many buffered bytes per direction.
    std::size_t max_probe_bytes = 4096;
};

class ParserRegistry {
public:
    void add(ParserFactory factory) { factories_.push_back(std::move(factory)); }
    const std::vector<ParserFactory>& factories() const { return factories_; }

    // Builds the reassembler's handler factory: every connection starts with a probing
    // handler that hands its buffered bytes to the first parser whose probe matches.
    // The registry and sink must outlive the returned factory.
    HandlerFactory handler_factory(EventSink& sink, DispatcherConfig config = {}) const;

private:
    std::vector<ParserFactory> factories_;
};

}  // namespace netaudit
