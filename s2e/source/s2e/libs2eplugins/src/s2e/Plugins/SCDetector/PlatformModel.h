#ifndef SRC_PLATFORMMODEL_H
#define SRC_PLATFORMMODEL_H

#include "SCDetector.h"

class PlatformModel {
public:
    virtual bool isOutOfStack(uint64_t addr, uint8_t size, const s2e::S2EExecutionState *state) = 0;

    virtual bool isLikelyToBeAPointer(uint64_t data, uint8_t size) = 0;

    virtual bool onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) { return true; };

    virtual bool killOnException(s2e::S2EExecutionState *state, unsigned int index, uint64_t pc) { return false; };

    virtual bool isPcAllowed(s2e::S2EExecutionState *state, uint64_t pc) { return true; };

    virtual bool onKillPoint(s2e::S2EExecutionState *state, uint64_t pc) { return true; };

    explicit PlatformModel(s2e::plugins::Propagator *scd) { this->scd = scd; }

protected:
    s2e::plugins::Propagator *scd;
};

#endif //SRC_PLATFORMMODEL_H
#ifndef SRC_PLATFORMMODEL_H
#define SRC_PLATFORMMODEL_H

#include "SCDetector.h"

class PlatformModel {
public:
    virtual bool isOutOfStack(uint64_t addr, uint8_t size, const s2e::S2EExecutionState *state) = 0;

    virtual bool isLikelyToBeAPointer(uint64_t data, uint8_t size) = 0;

    virtual bool onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) { return true; };

    virtual bool killOnException(s2e::S2EExecutionState *state, unsigned int index, uint64_t pc) { return false; };

    virtual bool isPcAllowed(s2e::S2EExecutionState *state, uint64_t pc) { return true; };

    virtual bool onKillPoint(s2e::S2EExecutionState *state, uint64_t pc) { return true; };

    explicit PlatformModel(s2e::plugins::Propagator *scd) { this->scd = scd; }

protected:
    s2e::plugins::Propagator *scd;
};

#endif //SRC_PLATFORMMODEL_H
