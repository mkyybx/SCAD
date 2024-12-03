#ifndef SRC_FREEBSDKERNELMODEL_H
#define SRC_FREEBSDKERNELMODEL_H

#include "PlatformModel.h"

class FreeBSDKernelModel : public PlatformModel {
private:
    uint64_t stackSize;
    uint64_t stackBase;
public:
    bool isOutOfStack(uint64_t addr, uint8_t size, const s2e::S2EExecutionState *state) override;

    bool isLikelyToBeAPointer(uint64_t data, uint8_t size) override;

    bool onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) override;

    explicit FreeBSDKernelModel(s2e::plugins::Propagator *scd) : PlatformModel(scd) {};
};


#endif //SRC_FREEBSDKERNELMODEL_H
