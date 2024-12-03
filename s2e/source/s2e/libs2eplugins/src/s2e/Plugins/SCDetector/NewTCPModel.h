#ifndef SRC_NEWTCPMODEL_H
#define SRC_NEWTCPMODEL_H

#include "ProtocolModel.h"

class NewTCPModel : public ProtocolModel {
protected:
    unsigned int skbPtrRegOff; // = R_EDI
    uint64_t offData2SkBuff; // = 224
    uint64_t offSport2Data = 0;
    uint64_t offDport2Data = 2;
    uint64_t offSeq2Data = 4;
    uint64_t offAck2Data = 8;
    uint64_t offDoff2Data = 12;
    uint64_t offFlags2Data = 13;
    uint64_t offWin2Data = 14;
    uint64_t offCksm2Data = 16;
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
    uint64_t tcpHdrSize;
//    unsigned int tcpHdrPtrRegOff;
//    unsigned int outputSkbPtrRegOff; // = R_EDI

    // Owner specific info
    int64_t offIpAddrLastB2Data; // = -5
    uint8_t attackerIPLastB = 16;
    uint8_t victimIPLastB = 1;
    const char *ipOwnerName = "ip_saddr_last_byte";
    std::string ipOwnerSymbolName;
    uint16_t atkrSport;
    uint16_t atkrNewSport;
    uint16_t vctmSport;
    uint16_t vctmNewSport;
    uint16_t srvPort;
    uint16_t closedPort;
    std::vector<klee::ref<klee::Expr>> saddr_last_byte_symbol;
    std::vector<klee::ref<klee::Expr>> sport_symbol;
    std::vector<klee::ref<klee::Expr>> opt_kind_symbol;
    std::vector<klee::ref<klee::Expr>> opt_len_symbol;
    std::vector<klee::ref<klee::Expr>> opt_data_symbol;

    // Model for differentiate listen and other sockets.
    std::unordered_map<uint64_t, unsigned int> skStateCheckPCRegOffs;
    uint8_t skStateListenEnumVal;
    uint64_t offSkState2Sk;

public:
    // Note this currently only models on tcp_v4_rcv and not in IPv6 and not in tcp_v4_err
    virtual void onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) override;

    virtual uint8_t getNewStateOwner(s2e::S2EExecutionState *oldState, s2e::S2EExecutionState* newState,
                             const std::vector<klee::ref<klee::Expr>> &newCond, s2e::plugins::Propagator *scd,
                             uint8_t oldOwner) override;

    virtual void onSkStateCheckPC(s2e::S2EExecutionState *state, uint64_t pc);

protected:
    explicit NewTCPModel(s2e::plugins::Propagator *scd);

private:
    klee::ref<klee::Expr> buildOptConstraint(uint8_t kind, uint8_t len);

    // Test only
    void onStateFork(s2e::S2EExecutionState *oldState, const std::vector<s2e::S2EExecutionState *> &newState,
                     const std::vector<klee::ref<klee::Expr>> &newCond);
};


#endif //SRC_NEWTCPMODEL_H
