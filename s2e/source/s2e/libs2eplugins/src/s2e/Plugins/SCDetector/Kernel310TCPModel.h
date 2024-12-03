#ifndef SRC_KERNEL310TCPMODEL_H
#define SRC_KERNEL310TCPMODEL_H

#include "TCPModel.h"

class Kernel310TCPModel : public TCPModel {
public:

    uint8_t getNewStateOwner(s2e::S2EExecutionState *oldState, s2e::S2EExecutionState *newState,
                             const std::vector<klee::ref<klee::Expr>> &newCond, s2e::plugins::Propagator *scd,
                             uint8_t oldOwner) override;

    explicit Kernel310TCPModel(s2e::plugins::Propagator *scd);
};


#endif //SRC_KERNEL310TCPMODEL_H
