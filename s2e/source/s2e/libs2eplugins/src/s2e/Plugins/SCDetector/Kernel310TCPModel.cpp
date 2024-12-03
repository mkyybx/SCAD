#include "Kernel310TCPModel.h"

Kernel310TCPModel::Kernel310TCPModel(s2e::plugins::Propagator *scd) : TCPModel(scd) {
    skbPtrRegOff = R_EDI;
    outputSkbPtrRegOff = R_EDI;
    offData2SkBuff = 224;
    offIpAddrLastB2Data = -5;
    offSkPtr2Skb = 0x18;
    offDestructorPtr2Skb = 0x80;
    offSkbHeadPtr2Skb = 0xd8;
    off_OffSkbEnd2SkbHead_2_Skb = 0xd0;
    skbSize = 240;
    offIpSummed2Skb = 124;
    offIpSummedBit = 2;
    offTransportHdr2Skb = 192;
    entryPoints.insert(0xffffffff81638390);
    outputPoints.insert(0xffffffff8162fc2c);
    terminatePoints.insert(0xffffffff81638411);
}

uint8_t Kernel310TCPModel::getNewStateOwner(s2e::S2EExecutionState *oldState,
                                            s2e::S2EExecutionState *newState,
                                            const std::vector<klee::ref<klee::Expr>> &newCond,
                                            s2e::plugins::Propagator *scd, uint8_t oldOwner) {
    if (oldOwner == (attackerOwner | victimOwner)) {
        return TCPModel::getNewStateOwner(oldState, newState, newCond, scd, oldOwner);
    } else {
        // This is a simplification as two path only separates at the very beginning.
        return oldOwner;
    }
}
