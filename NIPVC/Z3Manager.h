#ifndef SCDETECTOR2_Z3MANAGER_H
#define SCDETECTOR2_Z3MANAGER_H

#include <z3++.h>
#include "SolverManager.h"
#include "LRUCache.h"
#include "SyncQ.h"
#include <atomic>

using namespace std;
namespace SCDetector {
    class Z3Bundle;

    class Z3Manager : public SolverManager {
    private:
        SyncQ<shared_ptr<Z3Bundle>, SCD_THREADS> bundleQ;

        unordered_map<shared_ptr<Z3Bundle>, LRUCache<string, z3::expr>> cache;

    public:
        explicit Z3Manager(uint64_t lruCacheSize);

        shared_ptr<SolverBundle> getSolverBundle() override;

        void putSolverBundle(shared_ptr<SolverBundle> &bundle) override;

        void addSMT(const shared_ptr<SolverBundle> &bundle, const string &smt, bool reverse) override;

        void addFalseExpr(const shared_ptr<SolverBundle> &bundle) override;

        void addTrueExpr(const shared_ptr<SolverBundle> &bundle) override;

        SolverCheckResult checkSolver(const shared_ptr<SolverBundle> &bundle) override;

        string dumpSMT2(const shared_ptr<SolverBundle>& bundle) override;

        string dumpModel(const shared_ptr<SolverBundle>& bundle) override;
    };

    class Z3Bundle : public SolverBundle {
    private:
        friend class Z3Manager;

        unique_ptr<z3::context> z3ctx;
        unique_ptr<z3::solver> solver;

#ifdef DEBUGTEST
        uint64_t assertionCounter = 0;
#endif

        Z3Bundle();
    };
}

#endif //SCDETECTOR2_Z3MANAGER_H
