#include "GlobalVariables.h"
#include "ProgressPrinter.h"

using namespace std;
using namespace SCDetector;

void Global::init() {
    for (auto i = 0; i < SCD_THREADS; i++) {
        workerPermit.put(false);
        availableWorkerPermit++;
    }
    // Log
//    ProgressPrinter::getPrinter()->addKey(LOGNAME_GLOBAL_AVAIL_PERMITS, &availableWorkerPermit, &numOfThreads);
}

void Global::getWorkPermit() {
    workerPermit.get();
    availableWorkerPermit--;
}

void Global::putWorkPermit() {
    workerPermit.put(false);
    availableWorkerPermit++;
}

namespace SCDetector {
    SyncQ<bool, SCD_THREADS> Global::workerPermit;
    uint64_t Global::progressPrintInterval;
    unsigned Global::solverTimeout;
    bool Global::oneOwner;
    unordered_set<shared_ptr<Symbol>> Global::initSecrets;
    atomic<uint64_t> Global::availableWorkerPermit = 0;
    atomic<uint64_t> Global::numOfThreads = SCD_THREADS;
    atomic<uint64_t> Global::totalSymbols;
    shared_ptr<SolverManager> Global::solverManager;
    string Global::binaryImagePath;
    uint64_t Global::imageAddrOffset;
    uint64_t Global::maxTimeToRead;
    const unordered_map<uint64_t, string> Global::fkpTypeName = {{FKP_ROOT,                    "Root"},
                                                                 {FKP_TERM,                    "Finished"},
                                                                 {FKP_UNINIT,                  "Uninit"},
                                                                 {FKP_KILL_DISALLOWED_PC,      "Illegal pc"},
                                                                 {FKP_KILL_PARENT,             "FKP_KILL_PARENT"},
                                                                 {FKP_KILL_NA,                 "Added constraint"},
                                                                 {FKP_KILL_PANIC,              "Illegal state"},
                                                                 {FKP_KILL_ILLEGAL_MEM_ACC,    "Illegal memory"},
                                                                 {FKP_KILL_SYMBOL_MAKE_ERR,    "Symbolize err"},
                                                                 {FKP_KILL_INFEASIBLE_PATH,    "Infeasible path"},
                                                                 {FKP_KILL_LOOP,               "Loop terminate"},
                                                                 {FKP_KILL_TLE_SOLVER,         "Solver tle"},
                                                                 {FKP_KILL_TLE_EXEC,           "Block exec tle"},
                                                                 {FKP_KILL_TLE_CONC_EXEC,
                                                                                               "Concrete exec tle"},
                                                                 {FKP_KILL_GENERIC_LOGICAL,    "Generic logical kill"},
                                                                 {FKP_KILL_OTHER_OWNER,
                                                                                               "Path N/A for current owner"},
                                                                 {FKP_KILL_PREV_CONC_EXEC_TLE, "Prev concrete exec TLE"},
                                                                 {FKP_KILL_PREV_SOLVER_TLE,    "Prev solver TLE"},
                                                                 {FKP_KILL_GENERIC_SCOPE,      "Generic scope kill"},
                                                                 {FKP_UNFINISHED,              "Unfinished nodes"},
                                                                 {FKP_MIXED,                   "FKP_MIXED"}};
}
