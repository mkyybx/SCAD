#ifndef SCDETECTOR2_SOLVERMANAGER_H
#define SCDETECTOR2_SOLVERMANAGER_H

#include <memory>
#include <atomic>

using namespace std;

namespace SCDetector {
    class SolverBundle {

    };

    // Note this needs to be the same as Z3 under current implementation
    enum class SolverCheckResult {
        UNSAT,
        SAT,
        UNKNOWN,
    };

    class SolverManager {
    protected:
        atomic<uint64_t> compileTime = 0;
        atomic<uint64_t> compileCount = 0;
        atomic<uint64_t> cacheMissCount = 0;
        atomic<uint64_t> solveTime = 0;
        atomic<uint64_t> solveCount = 0;
        atomic<uint64_t> maxSolveTime = 0;

    public:
        SolverManager();

        virtual shared_ptr<SolverBundle> getSolverBundle() = 0;

        virtual void putSolverBundle(shared_ptr<SolverBundle> &bundle) = 0;

        virtual void addSMT(const shared_ptr<SolverBundle> &bundle, const string &smt, bool reverse) = 0;

        virtual void addFalseExpr(const shared_ptr<SolverBundle> &bundle) = 0;

        virtual void addTrueExpr(const shared_ptr<SolverBundle> &bundle) = 0;

        virtual SolverCheckResult checkSolver(const shared_ptr<SolverBundle> &bundle) = 0;

        virtual string dumpSMT2(const shared_ptr<SolverBundle>& bundle) = 0;

        virtual string dumpModel(const shared_ptr<SolverBundle>& bundle) = 0;

        virtual ~SolverManager() = default;
    };
}

#endif //SCDETECTOR2_SOLVERMANAGER_H
