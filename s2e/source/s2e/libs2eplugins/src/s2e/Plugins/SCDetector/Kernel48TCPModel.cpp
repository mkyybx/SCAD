#include "Kernel48TCPModel.h"
#include <netinet/in.h>

uint8_t Kernel48TCPModel::getNewStateOwner(s2e::S2EExecutionState *oldState,
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

Kernel48TCPModel::Kernel48TCPModel(s2e::plugins::Propagator *scd) : NewTCPModel(scd) {
    entryPoints.insert(0xffffffff81785b70);
    /* This is for tcp_transmit_skb and ip_build_and_send_pkt(tcp_send_synack). We are hooking on __tcp_v4_send_check as both funcs lead to __tcp_v4_send_check.
     * 0xffffffff817858aa <+26>:    add    r13,QWORD PTR [rdi+0xc8]
    *0xffffffff817858b1 <+33>:    and    eax,0x6
    */
    outputPoints.insert(0xffffffff817858b1);
    /* This is for ip_send_unicast_reply in tcp_v4_send_reset.
     * 0xffffffff8178297a <tcp_v4_send_reset+234>:  lea    r14,[rsp+0x60]
     * rsp+0x60 is tcp header
     * */
    outputPoints.insert(0xffffffff8178297a);
    /* This is for ip_send_unicast_reply in tcp_v4_send_ack.
     * 0xffffffff81782d1d <tcp_v4_send_ack+45>:     lea    r15,[rsp+0x34]
     * rsp+0x34 is tcp header
     * */
    outputPoints.insert(0xffffffff81782dee);
    // Fortunately, above functions in Kernel doesn't have push/pop before the hook point. Otherwise bp will change.

    terminatePoints.insert(0xffffffff81785c89);
    terminatePoints.insert(0xffffffff81785c96);
    terminatePoints.insert(0xffffffff81785ca3);
    terminatePoints.insert(0xffffffff81785cad);
    terminatePoints.insert(0xffffffff81785cbb);
    skbPtrRegOff = R_EDI;
//    outputSkbPtrRegOff = R_ESI;
    offData2SkBuff = 0xd0;
    offIpAddrLastB2Data = -5;
    offSkPtr2Skb = 0x18;
    offDestructorPtr2Skb = 0x60;
    offSkbHeadPtr2Skb = 0xc8;
    off_OffSkbEnd2SkbHead_2_Skb = 0xc4;
    skbSize = 224;
    offIpSummed2Skb = 0x89;
    offIpSummedBit = 1;

    /*
     * 0xffffffff81785dab <tcp_v4_rcv+571>: movzx  eax,BYTE PTR [r15+0x12]
     * Since the PC hook is on onTranslationStart, it should happen before execution. So we can use the location where sk_state is symbolized.
     * */
    skStateCheckPCRegOffs[0xffffffff81785dab] = 15;
    skStateListenEnumVal = 10;
    offSkState2Sk = 18;

    tcpHdrSize = 20; // Current no option is symbolized
}

s2e::plugins::GlobalWrite2 Kernel48TCPModel::onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) {
    uint64_t tcpHdrPtr;
    unsigned int tcpHdrPtrRegOff;
    if (pc == 0xffffffff817858b1) {
        tcpHdrPtrRegOff = 13;
    } else if (pc == 0xffffffff8178297a || pc == 0xffffffff81782dee) {
        tcpHdrPtrRegOff = R_ESP;
    } else {
        abort();
        // impossible
        return {};
    }
    if (!scd->readRegister64(state, tcpHdrPtrRegOff, &tcpHdrPtr, "read tcpHdrPtr on output function")) {
        return {};
    }
    if (pc == 0xffffffff8178297a) {
        tcpHdrPtr += 0x60;
    } else if (pc == 0xffffffff81782dee) {
        tcpHdrPtr += 0x34;
    }


    // Write check to 0
    uint16_t _zero = 0;
    if (!state->mem()->write(tcpHdrPtr + offCksm2Data, _zero)) {
        g_s2e->getDebugStream(state) << "Failed to write 0 to check sum in output function, pc=" << s2e::hexval(pc);
    }

    // Get TCP header, checksum should've been 0
    auto tcpHdr = s2e::plugins::Propagator::extendedRead(state, tcpHdrPtr, tcpHdrSize * 8); // 160 bits
    if (tcpHdr.isNull()) { // 8 bytes
        g_s2e->getDebugStream(state) << "Failed to access *tcpHdrPtr on output function pc="
                                     << s2e::hexval(pc) << ", tcpHdrPtr=\n"
                                     << s2e::hexval(tcpHdrPtr);
        return {};
    }


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

