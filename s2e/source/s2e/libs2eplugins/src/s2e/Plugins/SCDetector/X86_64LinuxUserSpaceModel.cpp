#include "X86_64LinuxUserSpaceModel.h"

bool X86_64LinuxUserSpaceModel::isLikelyToBeAPointer(uint64_t data, uint8_t size) {
    auto likely = (size == 8) && (((data & UINT64_C(0x7f0000000000)) == UINT64_C(0x7f0000000000)) ||
                                  ((data & UINT64_C(0x500000000000)) == UINT64_C(0x500000000000)));
    return likely || X86_64LinuxKernelModel::isLikelyToBeAPointer(data, size);
}

bool X86_64LinuxUserSpaceModel::isPcAllowed(s2e::S2EExecutionState *state, uint64_t pc) {
    auto cr3Expr = state->regs()->read(CPU_OFFSET(cr[3]), 8 * 8);
    if (isa<klee::ConstantExpr>(cr3Expr)) {
        uint64_t curCR3 = cast<klee::ConstantExpr>(cr3Expr)->getZExtValue(64);
        if (curCR3 == cr3) {
            return true;
        } else {
            g_s2e->getDebugStream(state) << "cr3 blocked execution\n";
            return false;
        }
    } else {
        g_s2e->getDebugStream(state) << "Error isPcAllowed reading CR3 failed.\n";
        return false;
    }
}

bool X86_64LinuxUserSpaceModel::onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) {
    // Must be concrete value
    bool err = false;
    auto magicNum = scd->readAndConcretizeMemory64(state, pc, err,
                                                   "This shouldn't appear: X86_64LinuxUserSpaceModel::onEntryFunction cannot read 8 bytes on entry pc.");
    if (err) {
        g_s2e->getDebugStream(state)
                << "Fatal: X86_64LinuxUserSpaceModel::onEntryFunction cannot read 8 bytes on entry pc.\n";
        exit(-1);
    }
    assert(scd->_8ByteAtEntryPc != 0);
    if (magicNum == scd->_8ByteAtEntryPc) {
        auto cr3Expr = state->regs()->read(CPU_OFFSET(cr[3]), 8 * 8);
        if (isa<klee::ConstantExpr>(cr3Expr)) {
            cr3 = cast<klee::ConstantExpr>(cr3Expr)->getZExtValue(64);
            g_s2e->getDebugStream(state) << "locked cr3 =" << s2e::hexval(cr3) << "\n";
            /*if (scd->stackStart != 0 && scd->stackEnd != 0) {
                g_s2e->getDebugStream(state) << "Use custom stack range =" << s2e::hexval(scd->stackStart) << " - "
                                             << s2e::hexval(scd->stackEnd) << "\n";
            }*/
            return X86_64LinuxKernelModel::onEntryFunction(state, pc);
        } else {
            g_s2e->getDebugStream(state) << "Fatal: X86_64LinuxUserSpaceModel::onEntryFunction cannot read cr3.\n";
            exit(-1);
        }
    } else {
        g_s2e->getDebugStream(state) << "magic num = " << s2e::hexval(magicNum) << ", expect "
                                     << s2e::hexval(scd->_8ByteAtEntryPc) << "\n";
        return false;
    }
}

bool X86_64LinuxUserSpaceModel::isOutOfStack(uint64_t addr, uint8_t size, const s2e::S2EExecutionState *state) {
/*    if (scd->stackStart == 0 && scd->stackEnd == 0) {*/
        return X86_64LinuxKernelModel::isOutOfStack(addr, size, state);
/*    } else {
        return (addr > scd->stackEnd || addr + size - 1 < scd->stackStart);
    }*/
}

bool X86_64LinuxUserSpaceModel::onKillPoint(s2e::S2EExecutionState *state, uint64_t pc) {
    if (cr3 == 0) {
        g_s2e->getDebugStream(state) << "cr3 = 0, allow kill.\n";
        return true;
    } else {
        auto cr3Expr = state->regs()->read(CPU_OFFSET(cr[3]), 8 * 8);
        if (isa<klee::ConstantExpr>(cr3Expr)) {
            uint64_t curCR3 = cast<klee::ConstantExpr>(cr3Expr)->getZExtValue(64);
            if (curCR3 == cr3) {
                return true;
            } else {
                g_s2e->getDebugStream(state) << "found kill on other process\n";
                return false;
            }
        } else {
            g_s2e->getDebugStream(state) << "Error onKillPoint reading CR3 failed, allow kill.\n";
            return true;
        }
    }
}
