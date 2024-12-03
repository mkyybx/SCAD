#include "Kernel44UDPModel.h"

uint8_t Kernel44UDPModel::getNewStateOwner(s2e::S2EExecutionState *oldState,
                                           s2e::S2EExecutionState *newState,
                                           const std::vector<klee::ref<klee::Expr>> &newCond,
                                           s2e::plugins::Propagator *scd, uint8_t oldOwner) {
    if (oldOwner == (attackerOwner | victimOwner)) {
        return UDPModel::getNewStateOwner(oldState, newState, newCond, scd, oldOwner);
    } else {
        // This is a simplification as two path only separates at the very beginning.
        return oldOwner;
    }
}

Kernel44UDPModel::Kernel44UDPModel(s2e::plugins::Propagator *scd) : UDPModel(scd) {
    skbPtrRegOff = R_EDI;
    outSkbPtrRegOff = R_ESI;
    offSkbHeadPtr2Skb = 0xc8;
    offTransportHdr2Skb = 0xba;
    offNetworkHdr2Skb = 0xbc;
    offSrcIPLastB2IpHdr = 0xf;
    offSkPtr2Skb = 0x18;
    offDestructorPtr2Skb = 0x60;
    off_OffSkbEnd2SkbHead_2_Skb = 0xc4;
    offIpSummed2Skb = 0x89;
    offIpSummedBit = 1;
    skbSize = 224;
    entryPoints.insert(0xffffffff81742ff0); // __udp4_lib_rcv
    outputPoints.insert(0xffffffff8173f642); // udp_send_skb
    outputPoints.insert(0xffffffff817467a0); // icmp_push_reply
//    outputPoints.insert(0xffffffff8171a600); // ip_send_skb
    terminatePoints.insert(0xffffffff81743094); // ret
    terminatePoints.insert(0xffffffff81743086); // pop stack before ret
    terminatePoints.insert(0xffffffff816b4a70); // kfree_skb
}

s2e::plugins::GlobalWrite2 Kernel44UDPModel::onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) {
    uint64_t addr;
    klee::ref<klee::Expr> summary;
    if (pc == 0xffffffff8173f642) {
        auto isCon = state->regs()->read(CPU_OFFSET(regs[13 * 8]), &addr, 8, false);    // 8 bytes
        if (!isCon) {
            auto sym = state->regs()->read(CPU_OFFSET(regs[13 * 8]), klee::Expr::Int64);
            if (state->regs()->read(CPU_OFFSET(regs[13 * 8]), &addr, 8, true)) {
                g_s2e->getDebugStream(state) << "concretizing addr on output function pc=" << s2e::hexval(pc) << ", skb="
                                             << s2e::hexval(addr) << "\n";
                scd->addConstraint(state, klee::EqExpr::create(sym, klee::ConstantExpr::create(addr, klee::Expr::Int64)), "output reg");
            } else {
                g_s2e->getDebugStream(state) << "Failed to concretize addr on output function pc=" << s2e::hexval(pc)
                                             << ", skb=\n"
                                             << state->regs()->read(CPU_OFFSET(regs[13 * 8]), klee::Expr::Int64);
                return {};
            }
        }
        summary = s2e::plugins::Propagator::extendedRead(state, addr, udpIcmpHdrSize * 8); // 160 bits
        if (summary.isNull()) { // 8 bytes
            g_s2e->getDebugStream(state) << "Failed to access *(headPtr + transportPtr) on output function pc="
                                         << s2e::hexval(pc) << ", headPtr + transportPtr=\n" << s2e::hexval(addr);
            return {};
        }
    } else if (pc == 0xffffffff817467a0) {
        auto isCon = state->regs()->read(CPU_OFFSET(regs[R_EDI]), &addr, 8, false);    // 8 bytes
        if (!isCon) {
            auto sym = state->regs()->read(CPU_OFFSET(regs[R_EDI]), klee::Expr::Int64);
            if (state->regs()->read(CPU_OFFSET(regs[R_EDI]), &addr, 8, true)) {
                g_s2e->getDebugStream(state) << "concretizing addr on output function pc=" << s2e::hexval(pc) << ", skb="
                                             << s2e::hexval(addr) << "\n";
                scd->addConstraint(state, klee::EqExpr::create(sym, klee::ConstantExpr::create(addr, klee::Expr::Int64)), "output reg");
            } else {
                g_s2e->getDebugStream(state) << "Failed to concretize addr on output function pc=" << s2e::hexval(pc)
                                             << ", skb=\n"
                                             << state->regs()->read(CPU_OFFSET(regs[R_EDI]), klee::Expr::Int64);
                return {};
            }
        }
        addr += 0x10;
        summary = s2e::plugins::Propagator::extendedRead(state, addr, udpIcmpHdrSize * 8); // 160 bits
        if (summary.isNull()) { // 8 bytes
            g_s2e->getDebugStream(state) << "Failed to access *(headPtr + transportPtr) on output function pc="
                                         << s2e::hexval(pc) << ", headPtr + transportPtr=\n" << s2e::hexval(addr);
            return {};
        }
    } else {
        return {};
    }
    auto tmp = s2e::plugins::GlobalWrite2();
    tmp.size = udpIcmpHdrSize;
    tmp.isOutput = true;
    tmp.pc = pc;
    tmp.summary = summary;
    tmp.cAddr = addr;
    tmp.stateID = state->getID();
    tmp.isPcPrecise = true;

    return tmp;
}
