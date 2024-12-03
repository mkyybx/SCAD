#ifndef SRC_KERNEL6132TCPMODEL_H
#define SRC_KERNEL6132TCPMODEL_H

#include "NewTCPModel.h"

class Kernel6132TCPModel : public NewTCPModel {
public:
    uint8_t getNewStateOwner(s2e::S2EExecutionState *oldState, s2e::S2EExecutionState *newState,
                             const std::vector<klee::ref<klee::Expr>> &newCond, s2e::plugins::Propagator *scd,
                             uint8_t oldOwner) override;

    explicit Kernel6132TCPModel(s2e::plugins::Propagator *scd);

    s2e::plugins::GlobalWrite2 onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) override;
};


#endif //SRC_KERNEL6132TCPMODEL_H
