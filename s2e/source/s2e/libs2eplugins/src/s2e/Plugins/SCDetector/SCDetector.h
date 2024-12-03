
#ifndef SRC_SCDETECTOR_H
#define SRC_SCDETECTOR_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Synchronization.h>
#include <s2e/cpu.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <llvm/Support/Casting.h>
#include <klee/Expr.h>

#include <utility>
#include "MyExecutionMonitor.h"
#include "MemRangeDetector.h"
#include "MyTracer.h"
#include <algorithm>

//#define PAGE_SIZE 4096
//#define THREAD_SIZE (PAGE_SIZE << 2)
//#define current_thread_info(ptr) (ptr & ~(THREAD_SIZE - 1))
//#define IP_OWNER_ATKR 0b01
//#define IP_OWNER_VCTM 0b10
//#define IP_OWNER_NAME "ip_saddr_last_byte"
//#define SRC_PORT 9638
//#define ATKR_DST_PORT 5555
//#define VCTM_DST_PORT 6666

#define FKP_ROOT UINT64_C(0xffffffffffffffff)
#define FKP_TERM UINT64_C(0xfffffffffffffffe)
#define FKP_UNINIT UINT64_C(0xfffffffffffffffd)
#define FKP_KILL_END UINT64_C(0xfffffffffffffffd)
#define FKP_KILL_DISALLOWED_PC UINT64_C(0xfffffffffffffffc)
#define FKP_KILL_PARENT UINT64_C(0xfffffffffffffffb) // parent of the dangling node when manually merging kills
#define FKP_KILL_NA UINT64_C(0xfffffffffffffffa) // for inserted medium nodes
#define FKP_KILL_PANIC UINT64_C(0xfffffffffffffff9)
#define FKP_KILL_ILLEGAL_MEM_ACC UINT64_C(0xfffffffffffffff8)
#define FKP_KILL_SYMBOL_MAKE_ERR UINT64_C(0xfffffffffffffff7)
#define FKP_KILL_INFEASIBLE_PATH UINT64_C(0xfffffffffffffff6)
#define FKP_KILL_LOOP UINT64_C(0xfffffffffffffff5)
#define FKP_KILL_TLE_SOLVER UINT64_C(0xfffffffffffffff4)
#define FKP_KILL_TLE_EXEC UINT64_C(0xfffffffffffffff3)
#define FKP_KILL_TLE_CONC_EXEC UINT64_C(0xfffffffffffffff2)
#define FKP_KILL_GENERIC_LOGICAL UINT64_C(0xfffffffffffffff1)
#define FKP_KILL_OTHER_OWNER UINT64_C(0xfffffffffffffff0)
#define FKP_KILL_PREV_CONC_EXEC_TLE UINT64_C(0xffffffffffffffef)
#define FKP_KILL_PREV_SOLVER_TLE UINT64_C(0xffffffffffffffee)
#define FKP_KILL_GENERIC_SCOPE UINT64_C(0xffffffffffffffed)
#define FKP_KILL_START UINT64_C(0xffffffffffffffec)
#define FKP_UNFINISHED UINT64_C(0xffffffffffffffeb)
#define FKP_MIXED UINT64_C(0xffffffffffffffea)

class ProtocolModel;

class PlatformModel;
namespace s2e {
    namespace plugins {
        class Secret {
        public:
            uint64_t addr{};
            uint8_t len{};
            std::string description;
            std::string name;

            Secret(uint64_t addr, uint8_t len, std::string description, std::string name) {
                this->description = std::move(description);
                this->addr = addr;
                this->len = len;
                this->name = std::move(name);
            }

            Secret() = default;
//            inline bool operator< (const Secret& other)
        };

        typedef Secret GlobalVar;
        typedef Secret NoForkPoint;

        class StateInfo {
        public:
            int id;
            std::set<klee::ref<klee::Expr>> constraints;
            StateInfo *parentState;
            std::set<klee::ref<klee::Expr>> secretRelatedConstraints;
        };

        class GlobalWrite2 {
        public:
            uint64_t cAddr;
            klee::ref<klee::Expr> sAddr;
            uint64_t pc;
            klee::ref<klee::Expr> summary;
            uint8_t *concreteSummaryBuffer; // used by output points
            uint bufferLen; // used by output points
            uint64_t stateID;
            uint8_t size;
            GlobalWrite2 *staledBy = nullptr;
            uint64_t forkedFromID;
            bool isOutput = false;
            bool fromOnSymbolic;
            bool isPcPrecise;

            std::string summaryBufferStr() const {
                std::stringstream ss;
                ss << "0x";
                for (auto i = 0; i < bufferLen; i++) {
                    ss << hexval(concreteSummaryBuffer[i]);
                }
                return ss.str();
            }
        };


        class OutputPoint {
        public:
            std::string name;
            uint64_t funcEntryAddr;
            uint8_t regOffset;
            uint8_t regLen;                // in bytes
            uint64_t structMemOffset;     // in bytes
            uint8_t structMemberLen;    // in bytes

            OutputPoint(std::string name, uint64_t funcEntryAddr, uint8_t regOffset, uint8_t regLen,
                        uint64_t structOffset, uint8_t structMemberLen) {
                this->name = std::move(name);
                this->funcEntryAddr = funcEntryAddr;
                this->regOffset = regOffset;
                this->regLen = regLen;
                this->structMemOffset = structOffset;
                this->structMemberLen = structMemberLen;
            }

            OutputPoint() {}
        };

        class PIDController {
            double kp;
            double ki;
            double kd;
            double previous_error;
            double cumulative_error;

        public:
            PIDController(double kp, double ki, double kd)
                    : kp(kp), ki(ki), kd(kd), previous_error(0.0), cumulative_error(0.0) {}

            double calculate(double setpoint, double measured_value) {
                double error = setpoint - measured_value;

                // Proportional term
                double p = kp * error;

                // Integral term
                cumulative_error += error;
                double i = ki * cumulative_error;

                // Derivative term
                double d = kd * (error - previous_error);

                previous_error = error;

                return p + i + d;
            }
        };

        class Propagator : public s2e::Plugin {
        S2E_PLUGIN

        public:

            class Range {
            public:
                uint64_t s;
                uint64_t e;
                uint64_t flags; // customized flags

                Range(uint64_t s, uint64_t e, uint64_t flags) {
                    this->s = s;
                    this->e = e;
                    this->flags = flags;
                    if (e < s) {
                        g_s2e->getDebugStream() << "Error: invalid range: " << s2e::hexval(s) << " - " << s2e::hexval(e)
                                                << "\n";
                        abort();
                    }
                }

                bool operator<(const Range &another) const {
                    return this->s < another.s;
                }

                bool operator==(const Range &another) const {
                    return this->s == another.s;
                }

                static bool sortRanges(std::vector<Range> &ranges) {
                    std::sort(ranges.begin(), ranges.end());

                    for (size_t i = 1; i < ranges.size(); ++i) {
                        if (ranges[i].s <= ranges[i - 1].e) {
                            // Ranges are overlapping, return false
                            g_s2e->getDebugStream() << "Range [" << ranges[i - 1].s << ", " << ranges[i - 1].e
                                                    << "] and range [" << ranges[i].s << ", " << ranges[i].e
                                                    << "] overlap.\n";
                            return false;
                        }
                    }
                    // No overlap, return true
                    return true;
                }

                static const Range *search(std::vector<Range> &ranges, uint64_t target) {
                    int left = 0;
                    int right = ranges.size() - 1;

                    while (left <= right) {
                        int mid = left + (right - left) / 2;

                        if (target < ranges[mid].s) {
                            right = mid - 1;
                        } else if (target > ranges[mid].e) {
                            left = mid + 1;
                        } else {
                            return &ranges[mid];
                        }
                    }

                    return nullptr;
                }

                static const Range *search(std::vector<Range> &ranges, uint64_t targetStart, uint8_t size) {
                    int left = 0;
                    int right = ranges.size() - 1;

                    while (left <= right) {
                        int mid = left + (right - left) / 2;

                        if (targetStart + size - 1 < ranges[mid].s) {
                            right = mid - 1;
                        } else if (targetStart > ranges[mid].e) {
                            left = mid + 1;
                        } else if (targetStart >= ranges[mid].s && targetStart + size - 1 <= ranges[mid].e) {
                            // If the range specified by 'targetStart' and 'size' is completely within a range
                            return &ranges[mid];
                        } else {
                            // If the range specified by 'targetStart' and 'size' is not completely within a range
                            return nullptr;
                        }
                    }

                    return nullptr;
                }
            };

            void initialize();

            Propagator(S2E *s2e) : Plugin(s2e) {}

            bool addConstraint(S2EExecutionState *state, const klee::ref<klee::Expr> &e, const std::string &reason);


            std::unordered_map<uint64_t, int8_t> symbolizedGlobalMem;
            std::unordered_map<uint64_t, std::unordered_map<uint64_t, bool>> noSymbolizeMem;

            // TODO: BUG: if the width = 19 * 8, then after read 16 bytes, the remaining 3 bytes will cause trouble
            static klee::ref<klee::Expr>
            extendedRead(s2e::S2EExecutionState *state, uint64_t address, uint width /*in bits*/,
                         AddressType addressType = VirtualAddress) {
                if (width == klee::Expr::Int8) {
                    return state->mem()->read(address, width, addressType);
                }
                auto ret = state->mem()->read(address, klee::Expr::Int8, addressType);
                width -= klee::Expr::Int8;
                address += klee::Expr::Int8 / 8;
                while (width >= klee::Expr::Int8) {
                    if (ret.isNull()) {
                        return nullptr;
                    }
                    ret = klee::ConcatExpr::create(ret, state->mem()->read(address, klee::Expr::Int8, addressType));
                    width -= klee::Expr::Int8;
                    address += klee::Expr::Int8 / 8;
                }
                if (ret.isNull()) {
                    return nullptr;
                }
                return width > 0 ? klee::ConcatExpr::create(ret, state->mem()->read(address, width, addressType)) : ret;
            }

            uint64_t
            readAndConcretizeMemory64(S2EExecutionState *state, uint64_t addr, bool &err, const std::string &reason);

            uint32_t
            readAndConcretizeMemory32(S2EExecutionState *state, uint64_t addr, bool &err, const std::string &reason);

            uint16_t
            readAndConcretizeMemory16(S2EExecutionState *state, uint64_t addr, bool &err, const std::string &reason);

            uint8_t
            readAndConcretizeMemory8(S2EExecutionState *state, uint64_t addr, bool &err, const std::string &reason);


            uint64_t getConcreteVal(S2EExecutionState *state, uintptr_t address, unsigned size, bool &failed) {
                auto summary = state->mem()->read(address, size * 8);
                klee::ref<klee::ConstantExpr> cVal;
                if (!summary.isNull()) {
                    if (isa<klee::ConstantExpr>(summary)) {
                        failed = false;
                        return cast<klee::ConstantExpr>(summary)->getZExtValue(size * 8);
                    } else {
                        getDebugStream(state) << "WARN: found mem read on:" << hexval(address) << "_" << size << "B:\n"
                                              << summary << "\n";
                    }
                } else {
                    getDebugStream(state) << "illegal mem acc @ " << hexval(address);
                }
                failed = true;
                return 0xdeafbeef;
            }

            void makeSymbolic(S2EExecutionState *state, uintptr_t address, unsigned size, const std::string &nameStr,
                              std::vector<klee::ref<klee::Expr>> *varData = nullptr, std::string *varName = nullptr) {
                if (!symbolizeMemory(state, 0, address, size, nameStr, varData, varName)) {
                    killIllegalState(state, "symbol make error", FKP_KILL_SYMBOL_MAKE_ERR);
                    exit(-1);
                }
            }

//            void
//            makeSymbolicOneByte(S2EExecutionState *state, uintptr_t address, unsigned size, const std::string &nameStr,
//                                std::vector<klee::ref<klee::Expr>> *varData = nullptr, std::string *varName = nullptr) {
//                auto pc = state->regs()->getPc();
//                for (auto i = 0; i < size; i++) {
//                    bool failed;
//                    std::vector<klee::ref<klee::Expr>> tmpVarData;
//                    auto cVal = getConcreteVal(state, address + i, 1, failed);
//                    if (failed) {
//                        killIllegalState(state, "symbol make error");
//                    }
//                    std::stringstream ss;
//                    ss << "gr_" << hexval(address + i) << "_1B_" << hexval(cVal) << "_PC_" << hexval(pc);
//                    m_base->makeSymbolic(state, address + i, 1, ss.str(), &tmpVarData, varName);
//                    symbolizedGlobalMemAccs[state->getID()][address + i] = 1;
//                    getDebugStream(state) << "[SYM]," << hexval(address + i) << "," << nameStr + "_" + std::to_string(i)
//                                          << "," << 1 << "," << hexval(cVal) << "," << hexval(pc) << "\n";
//                    assert(tmpVarData.size() == 1);
//                    if (varData != nullptr) {
//                        varData->push_back(tmpVarData[0]);
//                    }
//                }
//            }
//
//            void makeSymbolicMultiBytes(S2EExecutionState *state, uintptr_t address, unsigned size,
//                                        const std::string &nameStr,
//                                        std::vector<klee::ref<klee::Expr>> *varData = nullptr,
//                                        std::string *varName = nullptr) {
//                auto pc = state->regs()->getPc();
//                bool failed;
//                auto cVal = getConcreteVal(state, address, size, failed);
//                if (failed) {
//                    killIllegalState(state, "symbol make error");
//                }
//                std::stringstream ss;
//                ss << "gr_" << hexval(address) << "_" << (uint) size << "B_" << hexval(cVal) << "_PC_" << hexval(pc);
//                m_base->makeSymbolic(state, address, size, ss.str(), varData, varName);
//                // we still need to record every individual byte we symbolized to notice the unaligned memory access
//                for (auto i = 0; i < size; i++) {
//                    symbolizedGlobalMemAccs[state->getID()][address + i] = 1;
//                }
//                getDebugStream(state) << "[SYM]," << hexval(address) << "," << nameStr << "," << (uint) size << ","
//                                      << hexval(cVal) << "," << hexval(pc) << "\n";
//            }

            void killIllegalState(S2EExecutionState *state, const std::string &strReason, uint64_t fkid) {
                forceKilledStates[state->getID()] = fkid;
                s2e()->getExecutor()->terminateState(*state, strReason);
            }

//            uint8_t attackerIP;
//            uint8_t victimIP;


            std::vector<Range> disallowedGWRanges;
//            std::string ipOwnerSymbolName;

            std::unordered_map<uint64_t, uint8_t> pathOwner;
            uint64_t finishedStatesCountByOwner[2] = {0, 0};
            uint8_t weakOwner = 1;
            bool unconditionalFork;
            MyExecutionMonitor *m_monitor;
            uint64_t _8ByteAtEntryPc = 0;
            uint64_t stackStart = 0;
            uint64_t stackEnd = 0;

            void onTimeout(S2EExecutionState *state, CorePlugin::TimeoutReason r);

            bool
            readRegister64(S2EExecutionState *state, unsigned int regOff, uint64_t *val, const std::string &reason);

//            bool readCR3(S2EExecutionState *state, uint64_t *val, const std::string &reason);

        private:
            BaseInstructions *m_base;
            MyTracer *m_tracer;
            bool inited = false;
            bool forkOnMemAcc = false;
            bool oneByteMemAcc = false;
            ProtocolModel *model;
            std::string platModelString;
            PlatformModel *platModel;
            uint64_t lastForkTime;
            uint64_t lastForkTimeState;
//            uint64_t lastOnBeforeSymbolicMemAccAddr = 0;
            bool printConcretizationFKG;
            bool verboseBlockExecutionLog;
            uint32_t concreteExecTimeout;
            uint32_t blockExecTimeout;
            uint32_t loopDetectionRange;
            uint32_t loopDetectionTimes = 2;

            // Solver timeout adjust
            uint64_t currentTimeout = 0;
            uint64_t timeoutStateCounts = 0;
            uint64_t timeoutStatePercentage = 0;
            uint64_t minSolverTimeout = 0;
            uint64_t feedBackScale = 0;
            PIDController *solverTimeoutPidController = 0;
            uint64_t localScopeKilledPathCount = 0;
            uint64_t localFinishedPathCount = 0;

            std::unordered_map<uint64_t, std::unordered_set<uint>> testPCAndRegs;
            std::unordered_map<std::string, Secret> secrets;
            std::unordered_map<uint64_t, GlobalVar> globalVars;
            std::unordered_map<uint64_t, OutputPoint> outputPoints;
            // nullptr is not allowed
            std::unordered_map<uint64_t, std::unordered_map<uint64_t, std::shared_ptr<GlobalWrite2>>> globalWrites; // TODO: no support on symbolic addr
            std::unordered_map<uint64_t, std::vector<uint64_t>> forkPoints;
            std::vector<Range> goodPcRanges;
            std::vector<Range> badPcRanges;
            std::unordered_set<uint64_t> symbolicPointerForkPoints;
            std::set<uint64_t> disallowedGWAddrs; //TODO: we assume the write width is the same when comparing. We should add size info into this set if needed.
            std::unordered_map<uint64_t, uint64_t> forceKilledStates;
            std::unordered_map<uint64_t, uint64_t> symAddrForkedTimes;
            std::unordered_map<uint64_t, uint64_t> instructionCount;
            std::unordered_map<uint64_t, uint64_t> parentState;
            std::unordered_map<uint64_t, uint64_t> forkedFrom; // stateID->forkingEdgeID
//            std::unordered_map<uint64_t, bool> keepConcrete; // note we assume concrete states will never fork
            std::unordered_set<uint64_t> encounteredSPConcretization; // log purpose, no need to strictly sync among diff processes
            std::unordered_set<uint64_t> cbExecTLEPCs; // no need to strictly sync among diff processes
//            uint64_t totalInsCount = 0;
            std::unordered_map<uint64_t, uint64_t> pcAtInterrupt; // The pc when interrupt happens
            std::unordered_map<uint64_t, uint64_t> allowedSymbolicAddressPC; // Tell onStateFork if we are forking on symbolic address

            void onAfterSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> virtAddr,
                                                 klee::ref<klee::Expr> hostAddr, klee::ref<klee::Expr> val,
                                                 unsigned flags);

            void onStateFork(S2EExecutionState *oldState, const std::vector<S2EExecutionState *> &newState,
                             const std::vector<klee::ref<klee::Expr>> &newCond);

            void onStateForkDecide(S2EExecutionState *oldState, bool *doFork);

            void onStateKill(S2EExecutionState *state);

            void onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t virtAddr, uint64_t &val, uint8_t size,
                                            unsigned flags);

            void onBeforeSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> vAddr,
                                                  klee::ref<klee::Expr> val, bool isWrite);

            void
            onMemoryAccess(bool isConcrete, S2EExecutionState *state, uint64_t cVirtAddr, unsigned flags, uint8_t size,
                           bool oneByteMemAcc);

            void onTranslateBlockStart(ExecutionSignal *sig, S2EExecutionState *state, TranslationBlock *tb,
                                       uint64_t pc/* instruction PC */);

            void onBlockExecution(S2EExecutionState *state, uint64_t pc/* instruction PC */);

            void onSymbolicAddress(S2EExecutionState *state, klee::ref<klee::Expr> vAddr, uint64_t cAddr,
                                   bool &shouldConcretize, CorePlugin::symbolicAddressReason reason);

            void
            onBeforeSymbolicAddress(S2EExecutionState *state, klee::ref<klee::Expr> castedAddress, bool &doConcretize,
                                    CorePlugin::symbolicAddressReason);

            void onEntryFunction(S2EExecutionState *state, uint64_t pc);

            void onOutputFunction(S2EExecutionState *state, uint64_t pc);

            void onPreviousTLEPC(S2EExecutionState *state, uint64_t pc);

            void terminateState(S2EExecutionState *state, uint64_t pc);

            GlobalWrite2 getOutputSummaryTcpLinux310(llvm::raw_ostream &s, S2EExecutionState *state, uint64_t pc);

            void onMallocFunction(S2EExecutionState *state, uint64_t pc);

            void onKillPoint(S2EExecutionState *state, uint64_t pc);

            void onTestPc(S2EExecutionState *state, uint64_t pc);

            void onException(S2EExecutionState *state, unsigned index, uint64_t pc);

            void onEngineShutdown();

            std::set<klee::ref<klee::Expr>> *traverseConstraint(const klee::ref<klee::Expr> &);

            bool traverseConstraintSecretCheck(const klee::ref<klee::Expr> &, std::string *secretName);

            static std::string getSymName(klee::ref<klee::Expr> value);

//            std::string dumpQueryString(S2EExecutionState *state, klee::ConstraintManager &mgr);

            std::string dumpSingleQueryString(S2EExecutionState *state, const klee::ref<klee::Expr> &expr);

            std::string dumpSetValue(S2EExecutionState *state);

            void cleanMemory(S2EExecutionState *state);

            static void replaceAll(std::string &str, const std::string &from, const std::string &to);

            void onStateSplit(klee::StateSet &parent, klee::StateSet &child);

            void onProcessForkDecide(bool *proceed);

            klee::Z3Solver *solver;

            bool
            symbolizeMemory(S2EExecutionState *state, unsigned int flags, uint64_t cVirtAddr, uint8_t size,
                            const std::string &nameStr = "", std::vector<klee::ref<klee::Expr>> *varData = nullptr,
                            std::string *varName = nullptr);

            void onMemoryWrite(S2EExecutionState *state, uint64_t cVirtAddr, uint8_t size);

            void printFKGForAddedConstraint(S2EExecutionState *state, const klee::ref<klee::Expr> &e);

            bool checkStateFeasibleAndRecomputeConcolics(S2EExecutionState *state);

            void NO_USE_GET_STACK_BOTTOM_USING_BP(S2EExecutionState *state);

            bool isPcAllowed(S2EExecutionState *state, uint64_t pc);

            // need operator>, <, <=
//            template<class T, class U>
//            static unsigned long binarySearch(std::vector<T> &a, U &item, unsigned long low, unsigned long high) {
//                if (low >= high) {
//                    return low;
//                }
//                unsigned long mid = (low + high) / 2;
//                if (a[mid] > item) {
//                    return binarySearch(a, item, low, mid - 1);
//                } else if (a[mid] < item) {
//                    if (mid == 0 && high == 1) {
//                        if (a[high] <= item) {
//                            return high;
//                        } else {
//                            return mid;
//                        }
//                    }
//                    return binarySearch(a, item, mid, high);
//                } else {
//                    return mid;
//                }
//            }

            void getForkingSeq(uint64_t curState, std::stringstream &ss) {
                while (parentState.find(curState) != parentState.end()) {
                    auto parent = parentState[curState];
                    ss << parent << " ";
                    curState = parent;
                }
            }

            void updateSolverTimeout(S2EExecutionState *state);
        };


    }
}

#endif //SRC_SCDETECTOR_H
