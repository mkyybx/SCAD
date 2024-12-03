#ifndef SRC_WINDOWSSERVERTCPMODEL_H
#define SRC_WINDOWSSERVERTCPMODEL_H

#include "ProtocolModel.h"

class WindowsServerTCPModel : public ProtocolModel {
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
    std::vector<klee::ref<klee::Expr>> opt_kind_symbol;
    std::vector<klee::ref<klee::Expr>> opt_len_symbol;
    std::vector<klee::ref<klee::Expr>> opt_data_symbol;

    void symbolizingInput(s2e::S2EExecutionState *state, uint64_t pc);

    klee::ref<klee::Expr> buildOptConstraint(uint8_t kind, uint8_t len);

public:
    explicit WindowsServerTCPModel(s2e::plugins::Propagator *scd);

    void onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) override;

    s2e::plugins::GlobalWrite2 onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) override;

    uint8_t getNewStateOwner(s2e::S2EExecutionState *oldState, s2e::S2EExecutionState *newState,
                             const std::vector<klee::ref<klee::Expr>> &newCond, s2e::plugins::Propagator *scd,
                             uint8_t oldOwner) override;
};


#endif //SRC_WINDOWSSERVERTCPMODEL_H
