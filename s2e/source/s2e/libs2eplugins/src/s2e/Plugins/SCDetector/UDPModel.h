#ifndef SRC_UDPMODEL_H
#define SRC_UDPMODEL_H

#include "ProtocolModel.h"

class UDPModel : public ProtocolModel {
public:
    void onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) override;

    s2e::plugins::GlobalWrite2 onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) override;

    uint8_t getNewStateOwner(s2e::S2EExecutionState *oldState, s2e::S2EExecutionState *newState,
                             const std::vector<klee::ref<klee::Expr>> &newCond, s2e::plugins::Propagator *scd,
                             uint8_t oldOwner) override;

protected:
    unsigned int skbPtrRegOff;
    unsigned int outSkbPtrRegOff; // = R_ESI
    uint64_t offSkbHeadPtr2Skb;
    uint64_t offTransportHdr2Skb;
    uint64_t offNetworkHdr2Skb;
    uint64_t offSrcIPLastB2IpHdr;
    uint64_t offSkPtr2Skb;
    uint64_t offDestructorPtr2Skb;
    uint64_t off_OffSkbEnd2SkbHead_2_Skb;
    uint64_t skbSize;
    uint64_t udpIcmpHdrSize = 8;
    uint64_t offSport = 0;
    uint64_t offDport = 2;
    uint64_t offLen = 4;
    uint64_t offIpSummed2Skb;
    unsigned int offIpSummedBit;

    // owner specific
    std::string ipOwnerSymbolName;
    const char *ipOwnerName = "ip_saddr_last_byte";
    uint8_t attackerIPLastB = 16;
    uint8_t victimIPLastB = 1;
    uint16_t srcport;
    uint16_t attackerDstPort;
    uint16_t victimDstPort;
    uint16_t nonExistDsrPort;
    uint16_t listenDsrPort;
    std::vector<klee::ref<klee::Expr>> saddr_last_byte_symbol;

    explicit UDPModel(s2e::plugins::Propagator *scd);
};


#endif //SRC_UDPMODEL_H
