#ifndef SCDETECTOR2_YICESMANAGER_H
#define SCDETECTOR2_YICESMANAGER_H

#include "SolverManager.h"
#include "yices.h"
#include "SyncQ.h"
#include "LRUCache.h"

using namespace std;
namespace SCDetector {
    class YicesBundle;

    class YicesManager : public SolverManager {
    private:
        SyncQ<shared_ptr<YicesBundle>, SCD_THREADS> bundleQ;

        unordered_map<shared_ptr<YicesBundle>, LRUCache<string, term_t>> cache;

    public:
        explicit YicesManager(uint64_t lruCacheSize);

        shared_ptr<SolverBundle> getSolverBundle() override;

        void putSolverBundle(shared_ptr<SolverBundle> &bundle) override;

        void addSMT(const shared_ptr<SolverBundle> &bundle, const string &smt, bool reverse) override;

        void addFalseExpr(const shared_ptr<SolverBundle> &bundle) override;

        void addTrueExpr(const shared_ptr<SolverBundle> &bundle) override;

        SolverCheckResult checkSolver(const shared_ptr<SolverBundle> &bundle) override;

        string dumpSMT2(const shared_ptr<SolverBundle> &bundle) override;

        string dumpModel(const shared_ptr<SolverBundle> &bundle) override;

    };

    class YicesBundle : public SolverBundle {
    private:
        friend class YicesManager;

        context_t *ctx;

        YicesBundle();

    public:
        ~YicesBundle();
    };
} // SCDetector

#endif //SCDETECTOR2_YICESMANAGER_H
