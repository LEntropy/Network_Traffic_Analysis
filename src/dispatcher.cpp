#include "netaudit/dispatcher.hpp"

#include <algorithm>

namespace netaudit {

namespace {

class ProbingHandler : public StreamHandler {
public:
    ProbingHandler(const ConnectionInfo& info, const std::vector<ParserFactory>& factories,
                   EventSink& sink, DispatcherConfig config)
        : info_(info), factories_(factories), sink_(sink), config_(config) {}

    void on_data(Direction dir, const std::uint8_t* data, std::size_t len,
                 TimestampUs ts) override {
        if (parser_) {
            parser_->on_data(dir, data, len, ts);
            return;
        }
        if (gave_up_) return;

        std::string& seen = dir == Direction::ClientToServer ? client_ : server_;
        const std::size_t keep = std::min(len, config_.max_probe_bytes - seen.size());
        seen.append(reinterpret_cast<const char*>(data), keep);
        chunks_.push_back(Chunk{dir, ts, std::string(reinterpret_cast<const char*>(data), len)});

        try_probe();
    }

    void on_gap(Direction dir, std::uint64_t bytes, TimestampUs ts) override {
        if (parser_) {
            parser_->on_gap(dir, bytes, ts);
            return;
        }
        // Cannot recognise a protocol from a stream with a hole at its start.
        give_up();
    }

    void on_close(CloseReason reason, TimestampUs ts) override {
        if (!parser_ && !gave_up_) {
            // Short connections may close before a probe returned Match/NoMatch.
            try_probe(/*final=*/true);
        }
        if (parser_) parser_->on_close(reason, ts);
    }

    bool wants_data() const override { return parser_ ? parser_->wants_data() : !gave_up_; }

private:
    struct Chunk {
        Direction dir;
        TimestampUs ts;
        std::string bytes;
    };

    void try_probe(bool final = false) {
        const ProbeInput input{client_, server_};
        bool any_need_more = false;
        for (const ParserFactory& f : factories_) {
            const ProbeResult r = f.probe(input);
            if (r == ProbeResult::Match) {
                start_parser(f);
                return;
            }
            if (r == ProbeResult::NeedMore) any_need_more = true;
        }
        const bool full = client_.size() >= config_.max_probe_bytes ||
                          server_.size() >= config_.max_probe_bytes;
        if (!any_need_more || full || final) give_up();
    }

    void start_parser(const ParserFactory& f) {
        parser_ = f.create(info_, sink_);
        // Replay what was buffered while probing, in arrival order.
        std::vector<Chunk> chunks = std::move(chunks_);
        chunks_.clear();
        for (const Chunk& c : chunks) {
            if (!parser_->wants_data()) break;
            parser_->on_data(c.dir, reinterpret_cast<const std::uint8_t*>(c.bytes.data()),
                             c.bytes.size(), c.ts);
        }
        client_.clear();
        server_.clear();
    }

    void give_up() {
        gave_up_ = true;
        chunks_.clear();
        client_.clear();
        server_.clear();
    }

    ConnectionInfo info_;
    const std::vector<ParserFactory>& factories_;
    EventSink& sink_;
    DispatcherConfig config_;

    std::string client_;
    std::string server_;
    std::vector<Chunk> chunks_;
    std::unique_ptr<StreamHandler> parser_;
    bool gave_up_ = false;
};

}  // namespace

HandlerFactory ParserRegistry::handler_factory(EventSink& sink, DispatcherConfig config) const {
    return [this, &sink, config](const ConnectionInfo& info) -> std::unique_ptr<StreamHandler> {
        if (factories_.empty()) return nullptr;
        return std::make_unique<ProbingHandler>(info, factories_, sink, config);
    };
}

}  // namespace netaudit
