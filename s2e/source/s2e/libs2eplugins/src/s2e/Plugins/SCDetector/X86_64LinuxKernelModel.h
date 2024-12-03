#ifndef SRC_X86_64LINUXKERNELMODEL_H
#define SRC_X86_64LINUXKERNELMODEL_H

#include "PlatformModel.h"
#include "SCDetector.h"

class X86_64LinuxKernelModel : public PlatformModel {
public:
    bool isOutOfStack(uint64_t addr, uint8_t size, const s2e::S2EExecutionState *state) override;

    bool isLikelyToBeAPointer(uint64_t data, uint8_t size) override;

    bool onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) override;

    explicit X86_64LinuxKernelModel(s2e::plugins::Propagator *scd) : PlatformModel(scd) {};

protected:
    const uint64_t pageSize = 4096;
    const uint64_t threadSize = (pageSize << 2);
    uint64_t stackBase;

    inline uint64_t currentThreadInfo(uint64_t ptr) const;
};


#endif //SRC_X86_64LINUXKERNELMODEL_H
