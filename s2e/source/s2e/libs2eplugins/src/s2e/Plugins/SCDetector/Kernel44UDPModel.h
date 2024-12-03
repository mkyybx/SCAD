#ifndef SRC_KERNEL44UDPMODEL_H
#define SRC_KERNEL44UDPMODEL_H

#include "UDPModel.h"

class Kernel44UDPModel : public UDPModel {
public:
    uint8_t getNewStateOwner(s2e::S2EExecutionState *oldState, s2e::S2EExecutionState *newState,
                             const std::vector<klee::ref<klee::Expr>> &newCond, s2e::plugins::Propagator *scd,
                             uint8_t oldOwner) override;

    s2e::plugins::GlobalWrite2 onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) override;

    explicit Kernel44UDPModel(s2e::plugins::Propagator *scd);
};


#endif //SRC_KERNEL44UDPMODEL_H
