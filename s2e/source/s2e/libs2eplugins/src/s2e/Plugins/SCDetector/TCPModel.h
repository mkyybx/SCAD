#ifndef SRC_TCPMODEL_H
#define SRC_TCPMODEL_H

#include "ProtocolModel.h"

class TCPModel : public ProtocolModel {
protected:
    unsigned int skbPtrRegOff; // = R_EDI
    unsigned int outputSkbPtrRegOff; // = R_EDI
    uint64_t offData2SkBuff; // = 224
    uint64_t offSport2Data = 0;
    uint64_t offDport2Data = 2;
    uint64_t offSeq2Data = 4;
    uint64_t offAck2Data = 8;
    uint64_t offFlags2Data = 13;
    uint64_t offWin2Data = 14;
    uint64_t offUrgPtr2Data = 18;
    uint64_t offOption2Data = 20;
    uint64_t offSkPtr2Skb; // = 0x18
    uint64_t offDestructorPtr2Skb;
    uint64_t offSkbHeadPtr2Skb; // = 0xd8
    uint64_t off_OffSkbEnd2SkbHead_2_Skb; // = 0xd0
    uint64_t skbSize; // = 240
    uint64_t offIpSummed2Skb; // = 124;
    uint64_t offIpSummedBit; // = 2;

    // Output related variables: icsk->icsk_af_ops->queue_xmit in tcp_transmit_skb in tcp_output.c
    uint64_t offTransportHdr2Skb; // = 192
    uint64_t tcpHdrSize = 20;

    // Owner specific info
    int64_t offIpAddrLastB2Data; // = -5
    uint8_t attackerIPLastB = 16;
    uint8_t victimIPLastB = 1;
    const char *ipOwnerName = "ip_saddr_last_byte";
    uint16_t srcport;
    uint16_t attackerDstPort;
    uint16_t victimDstPort;
    uint16_t nonExistDsrPort;
    std::string ipOwnerSymbolName;
    std::vector<klee::ref<klee::Expr>> saddr_last_byte_symbol;

public:
    virtual void onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) override;

    virtual s2e::plugins::GlobalWrite2 onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) override;

    virtual uint8_t getNewStateOwner(s2e::S2EExecutionState *oldState, s2e::S2EExecutionState *newState,
                             const std::vector<klee::ref<klee::Expr>> &newCond, s2e::plugins::Propagator *scd,
                             uint8_t oldOwner) override;

protected:
    explicit TCPModel(s2e::plugins::Propagator *scd);
};

#endif //SRC_TCPMODEL_H
