#ifndef SCDETECTOR2_USING_H
#define SCDETECTOR2_USING_H

#include "SyncQ.h"
#include <unordered_set>

using namespace std;
namespace SCDetector {
    class PPGenInput;

    class SideChannelPropagations;

    class PartialPath;

    class GlobalWrite;

    class SideChannelPropagation;

    class Path;

    class ForkPoint;

    enum class PropagationType;

    class Symbol;

    class LogReaderWorkerOutput;

    using FPPRet = unordered_map<uint64_t, bool>;
    using FPPRes = unordered_map<uint64_t, unordered_map<string, vector<shared_ptr<PartialPath>>>>;
    using FPPReq = unordered_map<uint64_t, shared_ptr<GlobalWrite>>;
    using PPGenInputTag = tuple<shared_ptr<Symbol>, uint8_t>;
    using PPGenOutputTag = NoTag; //tuple<shared_ptr<Symbol>, shared_ptr<Symbol>, uint8_t, PropagationType>;
    using PPGenOutput = std::vector<std::shared_ptr<SideChannelPropagation>>;
    using PPGenInputQ = FairSyncMultiQ<shared_ptr<PPGenInput>, PPGenInputTag, SCD_THREADS * 2>;
    using PPGenOutputQ = FairSyncMultiQ<shared_ptr<PPGenOutput>, PPGenOutputTag, SCD_THREADS * 2>;

    /* [From Symbol][To Symbol]->(Set of possible global writes) */
    using DirectPropagationMap = unordered_map<shared_ptr<Symbol>, unordered_map<shared_ptr<Symbol>, shared_ptr<unordered_set<shared_ptr<GlobalWrite>>>>>;
    using Paths = unordered_map<uint64_t, shared_ptr<Path>>;
    using Fkid2GWS = unordered_map<uint64_t, unordered_map<uint64_t, shared_ptr<GlobalWrite>>>;
    using FkgStats = unordered_map<uint8_t, unordered_map<string, uint64_t>>;
    using Fkid2Fkp = unordered_map<uint8_t, unordered_map<uint64_t, shared_ptr<ForkPoint>>>;
    using Symbols = unordered_map<uint64_t, shared_ptr<Symbol>>;
    using GWSet = unordered_map<uint64_t, shared_ptr<GlobalWrite>>;

    using PropagationMap = unordered_map<shared_ptr<Symbol>, unordered_map<shared_ptr<Symbol>, SideChannelPropagations>>;
    using DijkstraPropagationMap = unordered_map<shared_ptr<Symbol>, unordered_map<shared_ptr<Symbol>, uint64_t>>;
    using PartialPathPair = array<shared_ptr<PartialPath>, 2>;
    using FkgHeads = unordered_map<uint8_t, shared_ptr<ForkPoint>>;

    using LogReaderWorkerInput = uint16_t;
    using LogReaderInputTag = NoTag;
    using LogReaderOutputTag = NoTag;
    using LogReaderInputQ = FairSyncMultiQ<shared_ptr<LogReaderWorkerInput>, LogReaderInputTag, SIZE_MAX>;
    using LogReaderOutputQ = FairSyncMultiQ<shared_ptr<LogReaderWorkerOutput>, LogReaderOutputTag, SCD_THREADS * 2>;

    using PPCheckInput = PPGenOutput;
    using PPCheckOutput = SideChannelPropagation;
    using PPCheckInputTag = PPGenOutputTag;
    using PPCheckOutputTag = NoTag;
    using PPCheckInputQ = PPGenOutputQ;
    using PPCheckOutputQ = FairSyncMultiQ<shared_ptr<PPCheckOutput>, PPCheckOutputTag, SCD_THREADS * 2>;

    using Prev = unordered_map<shared_ptr<Symbol>, shared_ptr<Symbol>>;
    using HighOrderPropagationMap = PropagationMap;

    using SNFInput = tuple<shared_ptr<Symbol>, uint8_t>;
    using SNFOutput = PPGenInput;
    using SNFInputTag = NoTag;
    using SNFOutputTag = PPGenInputTag;
    using SNFInputQ = FairSyncMultiQ<shared_ptr<SNFInput>, SNFInputTag, SCD_THREADS * 2>;
    using SNFOutputQ = PPGenInputQ;

    using ResultPrinterRet = std::tuple<shared_ptr<unordered_map<uint8_t, HighOrderPropagationMap>>, shared_ptr<unordered_map<shared_ptr<Symbol>, unordered_set<shared_ptr<Symbol>>>>>;

    using SCDLooperRet = std::tuple<uint64_t, shared_ptr<ResultPrinterRet>>;
}
#endif //SCDETECTOR2_USING_H
