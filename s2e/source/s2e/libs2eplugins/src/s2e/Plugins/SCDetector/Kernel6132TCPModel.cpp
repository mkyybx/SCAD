#include "Kernel6132TCPModel.h"

uint8_t Kernel6132TCPModel::getNewStateOwner(s2e::S2EExecutionState *oldState,
                                             s2e::S2EExecutionState *newState,
                                             const std::vector<klee::ref<klee::Expr>> &newCond,
                                             s2e::plugins::Propagator *scd, uint8_t oldOwner) {
    if (oldOwner == (attackerOwner | victimOwner)) {
        return NewTCPModel::getNewStateOwner(oldState, newState, newCond, scd, oldOwner);
    } else {
        // This is a simplification as two path only separates at the very beginning.
        return oldOwner;
    }
}

Kernel6132TCPModel::Kernel6132TCPModel(s2e::plugins::Propagator *scd) : NewTCPModel(scd) {
    entryPoints.insert(0xffffffff81a17500);
    /*
     * 0xffffffff81a17123 <+51>:    shr    eax,0x10
     * 0xffffffff81a17126 <+54>:    not    eax
     * 0xffffffff81a17128 <+56>:    mov    WORD PTR [rcx+rdx*1+0x10],ax
     * tcph ptr = rcx+rdx
     * For __tcp_v4_send_check (tcp_transmit_skb and ip_build_and_send_pkt(tcp_send_synack))
     * */
    outputPoints.insert(0xffffffff81a17123);
    /*
     * 0xffffffff81a15379 <tcp_v4_send_reset+137>:  mov    WORD PTR [rbp-0x70],ax
     * 0xffffffff81a153d0 <tcp_v4_send_reset+224>:  lea    r15,[rbp-0x70]
     * tcph ptr = rbp-0x70
     * This is for ip_send_unicast_reply in tcp_v4_send_reset.
     * The only option can be added is MD5SUM, which is not considered in our model.
     * */
    outputPoints.insert(0xffffffff81a153d0);
    /*
     * 0xffffffff81a14afb <tcp_v4_send_ack+75>:     lea    r10,[rbp-0x6c]
     * 0xffffffff81a14bc5 <tcp_v4_send_ack+277>:    mov    edx,0x20
     * 0xffffffff81a14bca <tcp_v4_send_ack+282>:    test   rsi,rsi
     * tcph ptr = rbp-0x6c
     * This is for ip_send_unicast_reply in tcp_v4_send_ack.
     * This should alreayd include the tsec option but not TCPMD5 which is out-of-scope
     * */
    outputPoints.insert(0xffffffff81a14bc5);
    terminatePoints.insert(0xffffffff81a17748); // csum_error
    terminatePoints.insert(0xffffffff81a1776d); // bad_packet
    terminatePoints.insert(0xffffffff81a17557); // discard_it
    terminatePoints.insert(0xffffffff81a17586); // end of tcp_v4_rcv
    terminatePoints.insert(0xffffffff81a17594); // end of tcp_v4_rcv
    skbPtrRegOff = R_EDI;
    offData2SkBuff = 0xd0;
    offIpAddrLastB2Data = -5;
    offSkPtr2Skb = 0x18;
    offDestructorPtr2Skb = 0x60;
    offSkbHeadPtr2Skb = 0xc8;
    off_OffSkbEnd2SkbHead_2_Skb = 0xc0;
    skbSize = 232;
    offIpSummed2Skb = 0x80;
    offIpSummedBit = 5;
    tcpHdrSize = 20;

    /*
     *  Since the PC hook is on onTranslationStart, it should happen before execution. So we can use the location where sk_state is symbolized.
     *  0xffffffff81a17a8e <tcp_v4_rcv+1422>:        movzx  edx,BYTE PTR [rax+0x12]
     *  */
    skStateCheckPCRegOffs[0xffffffff81a17a8e] = R_EAX;
    /*
     * 0xffffffff81a176c5 <tcp_v4_rcv+453>: movzx  eax,BYTE PTR [rbp+0x12]
     * */
    skStateCheckPCRegOffs[0xffffffff81a176c5] = R_EBP;
    skStateListenEnumVal = 10;
    offSkState2Sk = 18;
}

s2e::plugins::GlobalWrite2 Kernel6132TCPModel::onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) {
    uint64_t tcpHdrPtr;
    if (pc == 0xffffffff81a17123) {
        uint64_t rcx;
        if (!scd->readRegister64(state, R_ECX, &rcx, "tcp header pointer rcx on output function")) {
            return {};
        }
        uint64_t rdx;
        if (!scd->readRegister64(state, R_EDX, &rdx, "tcp header pointer rdx on output function")) {
            return {};
        }
        tcpHdrPtr = rcx + rdx;
    } else {
        if (!scd->readRegister64(state, R_EBP, &tcpHdrPtr, "tcp header pointer rbp on output function")) {
            return {};
        }
        if (pc == 0xffffffff81a153d0) {
            tcpHdrPtr -= 0x70;
        } else if (pc == 0xffffffff81a14bc5) {
            tcpHdrPtr -= 0x6c;
        } else {
            // impossible
            abort();
            return {};
        }
    }

    // Write check to 0
    uint16_t _zero = 0;
    if (!state->mem()->write(tcpHdrPtr + offCksm2Data, _zero)) {
        g_s2e->getDebugStream(state) << "Failed to write 0 to check sum in output function, pc=" << s2e::hexval(pc);
    }

    // Read doff
    bool err = false;
    auto doff = scd->readAndConcretizeMemory8(state, tcpHdrPtr + offDoff2Data, err, "Read data off in TCP output");
    doff >>= 4; // The remaining 12 bits are flags
    if (err) {
        g_s2e->getDebugStream(state) << "Failed to access *(th->doff) on output function pc=" << s2e::hexval(pc)
                                     << ", th->doff=\n" << s2e::hexval(tcpHdrPtr + offDoff2Data) << "\n";
        return {};
    } else {
        g_s2e->getDebugStream(state) << "doff=" << (unsigned) doff << "\n";
    }

    auto sizeToRead = doff * 4 >= tcpHdrSize ? tcpHdrSize : doff * 4;
    g_s2e->getDebugStream(state) << "read " << sizeToRead << " bytes on output\n";
    auto tcpHdr = s2e::plugins::Propagator::extendedRead(state, tcpHdrPtr, sizeToRead * 8); // 160 bits
    if (tcpHdr.isNull()) { // 8 bytes
        g_s2e->getDebugStream(state) << "Failed to access *(skb->data) on output function pc="
                                     << s2e::hexval(pc) << ", skb->data=\n"
                                     << s2e::hexval(tcpHdrPtr) << "\n";
        return {};
    }

    // Padding with option 1 to normalize the output length. This is required as all symbols should have equal length
    if (sizeToRead < tcpHdrSize) {
        for (auto i = 0; i < tcpHdrSize - sizeToRead; i++) {
            tcpHdr = klee::ConcatExpr::create(tcpHdr, klee::ConstantExpr::create(1, klee::Expr::Int8));
        }
    }
    // Now tcpHdr must be length of tcpHdrSize
    // Evaluate the concrete output
    g_s2e->getDebugStream(state) << "Concrete output: " << state->concolics->evaluate(tcpHdr) << "\n";

    auto tmp = s2e::plugins::GlobalWrite2();
    tmp.size = tcpHdrSize;
    tmp.isOutput = true;
    tmp.pc = pc;
    tmp.summary = tcpHdr;
    tmp.cAddr = tcpHdrPtr;
    tmp.stateID = state->getID();
    tmp.isPcPrecise = true;

    return tmp;
}
