#ifndef SRC_X86_64LINUXUSERSPACEMODEL_H
#define SRC_X86_64LINUXUSERSPACEMODEL_H

#include "X86_64LinuxKernelModel.h"

class X86_64LinuxUserSpaceModel : public X86_64LinuxKernelModel {
public:
    bool isLikelyToBeAPointer(uint64_t data, uint8_t size) override;

    bool isPcAllowed(s2e::S2EExecutionState *state, uint64_t pc) override;

    bool onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) override;

    bool isOutOfStack(uint64_t addr, uint8_t size, const s2e::S2EExecutionState *state) override;

    bool onKillPoint(s2e::S2EExecutionState *state, uint64_t pc) override;

    explicit X86_64LinuxUserSpaceModel(s2e::plugins::Propagator *scd) : X86_64LinuxKernelModel(scd) {};
private:
    uint64_t cr3 = 0;
};


#endif //SRC_X86_64LINUXUSERSPACEMODEL_H
