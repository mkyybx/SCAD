#include "Kernel6132UDPModel.h"

uint8_t Kernel6132UDPModel::getNewStateOwner(s2e::S2EExecutionState *oldState, s2e::S2EExecutionState *newState,
                                             const std::vector<klee::ref<klee::Expr>> &newCond,
                                             s2e::plugins::Propagator *scd, uint8_t oldOwner) {
    if (oldOwner == (attackerOwner | victimOwner)) {
        return UDPModel::getNewStateOwner(oldState, newState, newCond, scd, oldOwner);
    } else {
        // This is a simplification as two path only separates at the very beginning.
        return oldOwner;
    }
}

s2e::plugins::GlobalWrite2 Kernel6132UDPModel::onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) {
    uint64_t addr;
    klee::ref<klee::Expr> summary;
    if (pc == 0xffffffff81a21368) {
        // get udp_hdr
        uint64_t udpHdrPtr;
        if (!scd->readRegister64(state, 12 * 8, &udpHdrPtr, "udp header for output function")) {
            return {};
        }
        // read
        auto udpHdr = s2e::plugins::Propagator::extendedRead(state, udpHdrPtr, udpIcmpHdrSize * 8);
        if (udpHdr.isNull()) {
            g_s2e->getDebugStream(state) << "Failed to access *r12 on output function pc=" << s2e::hexval(pc)
                                         << ", r12=\n" << s2e::hexval(udpHdrPtr) << "\n";
            return {};
        }
        addr = udpHdrPtr;
        summary = udpHdr;
    } else if (pc == 0xffffffff81a29e70) {
        // get icmp_hdr
        uint64_t icmpParamPtr;
        if (!scd->readRegister64(state, R_ESI, &icmpParamPtr, "icmp header for output function")) {
            return {};
        }
        /* (gdb) print &(((struct icmp_bxm *)0)->data.icmph)
        * $3 = (struct icmphdr *) 0x10 <fixed_percpu_data+16>
         * */
        auto icmpHdr = s2e::plugins::Propagator::extendedRead(state, icmpParamPtr + 0x10, udpIcmpHdrSize * 8);
        if (icmpHdr.isNull()) {
            g_s2e->getDebugStream(state) << "Failed to access *(rsi+0x10) on output function pc=" << s2e::hexval(pc)
                                         << ", rsi=\n" << s2e::hexval(icmpParamPtr) << "\n";
            return {};
        }
        addr = icmpParamPtr + 0x10;
        summary = icmpHdr;
    } else {
        abort();
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

Kernel6132UDPModel::Kernel6132UDPModel(s2e::plugins::Propagator *scd) : UDPModel(scd) {
    skbPtrRegOff = R_EDI;
    offSkbHeadPtr2Skb = 0xc8;
    offTransportHdr2Skb = 0xb6;
    offNetworkHdr2Skb = 0xb8;
    offSrcIPLastB2IpHdr = 0xf;
    offSkPtr2Skb = 0x18;
    offDestructorPtr2Skb = 0x60;
    off_OffSkbEnd2SkbHead_2_Skb = 0xc0;
    skbSize = 232;
    offIpSummed2Skb = 0x80;
    offIpSummedBit = 5;
    // These two are dynamically chosen by OS. So it's per-image-base
    attackerDstPort = htobe16(38353);        // On victim server
    victimDstPort = htobe16(51138);          // On victim server


    entryPoints.insert(0xffffffff81a25460); // __udp4_lib_rcv
    terminatePoints.insert(0xffffffff81a25643); // 0xffffffff81a25643 <+483>:   add    rsp,0x38
    terminatePoints.insert(0xffffffff81a255fa); //  0xffffffff81a255fa <+410>:   add    rsp,0x38
    terminatePoints.insert(0xffffffff81a2563c); //  call   0xffffffff8193b850 <kfree_skb_reason>
    terminatePoints.insert(0xffffffff81a25cd8); //  call   0xffffffff8193b850 <kfree_skb_reason>
    terminatePoints.insert(0xffffffff81a25d3f); //  call   0xffffffff8193b850 <kfree_skb_reason>
    outputPoints.insert(
            0xffffffff81a21368); //  udp_send_skb, 0xffffffff81a21362 <+98>:    mov    WORD PTR [r12+0x6],ax, the instruction after this. r12 is the udp header
    outputPoints.insert(
            0xffffffff81a29e70); // first instruction of icmp_push_reply, rsi is the second arg: struct icmp_bxm *icmp_param
}
