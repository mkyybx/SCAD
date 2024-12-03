#ifndef SRC_PROTOCOLMODEL_H
#define SRC_PROTOCOLMODEL_H

#include "SCDetector.h"
class ProtocolModel {
public:
    virtual void onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) = 0;

    virtual s2e::plugins::GlobalWrite2
    onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) = 0;

    virtual uint8_t
    getNewStateOwner(s2e::S2EExecutionState *oldState, s2e::S2EExecutionState* newState,
                     const std::vector<klee::ref<klee::Expr>> &newCond, s2e::plugins::Propagator *scd,
                     uint8_t oldOwner) = 0;

    std::unordered_set<uint64_t> entryPoints;
    std::unordered_set<uint64_t> outputPoints;
    std::unordered_set<uint64_t> terminatePoints;
    std::unordered_set<std::string> symbolicPointerForkingSymbolNames;
    s2e::plugins::Propagator *scd;
    uint8_t defaultOwner;
    uint8_t attackerOwner;
    uint8_t victimOwner;

    explicit ProtocolModel(s2e::plugins::Propagator *scd) {
        this->scd = scd;
    }
};

#endif //SRC_PROTOCOLMODEL_H
