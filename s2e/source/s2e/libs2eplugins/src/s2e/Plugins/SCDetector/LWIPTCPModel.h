#ifndef SRC_LWIPTCPMODEL_H
#define SRC_LWIPTCPMODEL_H

#include "ProtocolModel.h"

class LWIPTCPModel : public ProtocolModel {
private:
    uint8_t attackerIPLastB;
    uint8_t victimIPLastB;
    uint16_t atkrSport;
    uint16_t atkrNewSport;
    uint16_t vctmSport;
    uint16_t vctmNewSport;
    uint16_t srvPort;
    uint16_t closedPort;
    uint16_t tcpHdrSize;
    std::vector<klee::ref<klee::Expr>> saddr_last_byte_symbol;
    uint64_t loadbase = 0x558860600000;
    uint64_t inputTcpHdr = 0x23f570;
    uint64_t inputIpLastBHdr = 0x240207;
public:
    void onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) override;

    s2e::plugins::GlobalWrite2 onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) override;

    uint8_t getNewStateOwner(s2e::S2EExecutionState *oldState, s2e::S2EExecutionState *newState,
                             const std::vector<klee::ref<klee::Expr>> &newCond, s2e::plugins::Propagator *scd,
                             uint8_t oldOwner) override;

    explicit LWIPTCPModel(s2e::plugins::Propagator *scd);
};


#endif //SRC_LWIPTCPMODEL_H
