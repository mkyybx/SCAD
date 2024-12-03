#include "FreeBSDKernelModel.h"

bool FreeBSDKernelModel::isOutOfStack(uint64_t addr, uint8_t size, const s2e::S2EExecutionState *state) {
    return (addr > stackBase + stackSize || addr + size - 1 < stackBase);
}

bool FreeBSDKernelModel::isLikelyToBeAPointer(uint64_t data, uint8_t size) {
    return size == 8 && (data & UINT64_C(0xfffff00000000000)) == UINT64_C(0xfffff00000000000) &&
           data != UINT64_C(0xffffffffffffffff);
}

bool FreeBSDKernelModel::onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) {
    stackSize = (1 << 12) * 4;
    stackBase = state->regs()->getSp() & ~(stackSize - 1);
    g_s2e->getDebugStream(state) << " stack_base = " << s2e::hexval(stackBase) << ", stack size = " << stackSize
                                 << "\n";
    return true;
}
