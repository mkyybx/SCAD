#include "X86_64LinuxKernelModel.h"

bool X86_64LinuxKernelModel::isOutOfStack(uint64_t addr, uint8_t size, const s2e::S2EExecutionState *state) {
    return (addr > stackBase + threadSize || addr + size - 1 < stackBase);
}

bool X86_64LinuxKernelModel::isLikelyToBeAPointer(uint64_t data, uint8_t size) {
    return size == 8 && (data & UINT64_C(0xff00000000000000)) == UINT64_C(0xff00000000000000) &&
           data != UINT64_C(0xffffffffffffffff);
}

uint64_t X86_64LinuxKernelModel::currentThreadInfo(uint64_t ptr) const {
    return ptr & ~(threadSize - 1);
}

bool X86_64LinuxKernelModel::onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) {
    auto sp = state->regs()->getSp();
    stackBase = currentThreadInfo(sp);
    g_s2e->getDebugStream(state) << " stack_base = " << s2e::hexval(stackBase) << "\n";
    return true;
}
