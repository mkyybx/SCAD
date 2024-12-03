#ifndef SCDETECTOR2_GLOBALVARIABLES_H
#define SCDETECTOR2_GLOBALVARIABLES_H

#include <unordered_map>
#include <unordered_set>
#include "SyncQ.h"
#include <atomic>
#include "SolverManager.h"

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

#define GW_OUTPUT 0xdbeef

#define GW_MEMBER_NUM 11
#define PC_MEMBER_NUM 2
#define FKG_MEMBER_NUM 7
#define SYM_MEMBER_NUM 6

#define LOGNAME_LOGREADER "Log reader"
#define LOGNAME_CHECKER_FINISHED "Checker\tfinished jobs"
#define LOGNAME_CHECKER_TIMEOUT "Checker\ttimeout jobs"
#define LOGNAME_CHECKER_SKIPPED "Checker\tskipped jobs"
#define LOGNAME_CHECKER_TYPE "Checker\tjob types\t"
#define LOGNAME_LOOPER_NODECHECKED "Looper\tchecked nodes"
#define LOGNAME_SNFINDER_SNCHECKED "SNFinder\tchecked secnames\t"
#define LOGNAME_PRINTER_DIRECTPROPAGATION "Printer\tdirect propagations"
#define LOGNAME_PRINTER_ONESIDEPROPAGATION "Printer\tone side propagations"
#define LOGNAME_PRINTER_TWOSIDESPROPAGATION "Printer\ttwo sides propagations"
#define LOGNAME_Z3MANAGER_COMPILE_TIME "Z3Manager\tcompile Time"
#define LOGNAME_Z3MANAGER_CACHE_MISS_COUNT "Z3Manager\tcache miss"
#define LOGNAME_Z3MANAGER_MAX_SOLVE_TIME "Z3Manager\tmax solve time"
#define LOGNAME_Z3MANAGER_SOLVE_RATE "Z3Manager\tsolve rate (ms per op)"
#define LOGNAME_GLOBAL_AVAIL_PERMITS "Global\tavail. permits"
#define LOGNAME_WORKERPOOL_AVAIL_WORKERS "WorkerPool\tworking threads\t"
#define LOGNAME_WORKERPOOL_UNFINISHED_JOBS "WorkerPool\tunfinished jobs\t"
#define LOGNAME_PPGEN_WORKER_NAME "Partial Path Generator"
#define LOGNAME_SNFINDER_WORKER_NAME "Sec Node Finder"
#define LOGNAME_PPCHECKER_WORKER_NAME "Path Pair Checker"
#define LOGNAME_LOGREADER_WORKER_NAME "Log Reader"
#define LOGNAME_KNOWNRESULTS_ESTIMATION_VALID_SYMS "KnownResults\tvalid symbols"


#define SHADOW_VAR_SUFFIX "shadow"

#define GW_NW "NoWrite"
#define GW_NA "NA"

#define OWNER_ATTACKER 1
#define OWNER_VICTIM 2

#define LOG_CACHE_NAME "LogReader.bin"
#define SEC_NODE_FINDER_SUFFIX "snfinder.bin"

namespace SCDetector {
    class Symbol;
    class Global {
    private:
        static SyncQ<bool, SCD_THREADS> workerPermit;
        static atomic<uint64_t> availableWorkerPermit;
    public:
        static uint64_t progressPrintInterval;  // In seconds
        static unsigned solverTimeout;  // In ms
        static bool oneOwner;
        static unordered_set<shared_ptr<Symbol>> initSecrets;
        static atomic<uint64_t> numOfThreads;
        static atomic<uint64_t> totalSymbols;
        static const unordered_map<uint64_t, string> fkpTypeName;
        static shared_ptr<SolverManager> solverManager;
        static string binaryImagePath;
        static uint64_t imageAddrOffset;
        static uint64_t maxTimeToRead;

        static void init();

        static void getWorkPermit();

        static void putWorkPermit();
    };
}

#endif //SCDETECTOR2_GLOBALVARIABLES_H
