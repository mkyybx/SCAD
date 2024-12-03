#ifndef SRC_KERNEL48TCPMODEL_H
#define SRC_KERNEL48TCPMODEL_H

#include "NewTCPModel.h"

class Kernel48TCPModel : public NewTCPModel {
public:
    uint8_t getNewStateOwner(s2e::S2EExecutionState *oldState, s2e::S2EExecutionState *newState,
                             const std::vector<klee::ref<klee::Expr>> &newCond, s2e::plugins::Propagator *scd,
                             uint8_t oldOwner) override;

    s2e::plugins::GlobalWrite2 onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) override;

    explicit Kernel48TCPModel(s2e::plugins::Propagator *scd);
};


#endif //SRC_KERNEL48TCPMODEL_H
