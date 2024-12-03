#ifndef SRC_NTKERNELMODEL_H
#define SRC_NTKERNELMODEL_H

#include "PlatformModel.h"
#include "s2e/S2EExecutionState.h"

class NTKernelModel : public PlatformModel {
public:
    bool isOutOfStack(uint64_t addr, uint8_t size, const s2e::S2EExecutionState *state) override;

    bool isLikelyToBeAPointer(uint64_t data, uint8_t size) override;

    bool killOnException(s2e::S2EExecutionState *state, unsigned int index, uint64_t pc) override;

    explicit NTKernelModel(s2e::plugins::Propagator *scd) : PlatformModel(scd) {};
};


#endif //SRC_NTKERNELMODEL_H
