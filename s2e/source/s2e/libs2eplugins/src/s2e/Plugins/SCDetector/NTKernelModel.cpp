#include "NTKernelModel.h"
#include "s2e/S2E.h"
#include "s2e/Utils.h"

bool NTKernelModel::isOutOfStack(uint64_t addr, uint8_t size, const s2e::S2EExecutionState *state) {
    // get current sp
    /* However, a common value that has been consistent for quite some time in Windows for the size of the kernel-mode stack for a thread is 12KB for 32-bit systems (x86) and 24KB for 64-bit systems (x64).*/
    auto sp = state->regs()->getSp();
//    g_s2e->getDebugStream(state) << "sp=" << s2e::hexval(sp) << ", stack=" << s2e::hexval(sp - 12 * 1024) << "-"
//                                 << s2e::hexval(sp + 12 * 1024);
    return addr > sp + 12 * 1024 || addr + size - 1 < sp - 12 * 1024;
}

bool NTKernelModel::isLikelyToBeAPointer(uint64_t data, uint8_t size) {
    return size == 8 && (data & UINT64_C(0xffff000000000000)) == UINT64_C(0xffff000000000000) &&
           data != UINT64_C(0xffffffffffffffff);
}

bool NTKernelModel::killOnException(s2e::S2EExecutionState *state, unsigned int index, uint64_t pc) {
    // All INT_NUM between 0x0 and 0x1F, inclusive, are reserved for exceptions; INT_NUM bigger than 0x1F are used for interrupt routines.
    if (index != 14) {
        return true;
    } else {
        return false;
    }
}
