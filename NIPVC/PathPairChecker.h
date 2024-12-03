#ifndef SCDETECTOR2_PATHPAIRCHECKER_H
#define SCDETECTOR2_PATHPAIRCHECKER_H

#include <atomic>
#include "BasicType.h"
#include "WorkerPool.h"
#include "KnownResults.h"
#include "Using.h"
#include "Worker.h"

using namespace std;
namespace SCDetector {
    class PathPairChecker : public Worker {
    private:
        void checkingWorker(const shared_ptr<PPCheckInputQ> &inputQ, const shared_ptr<PPCheckOutputQ> &outputQ);

        atomic<uint64_t> submittedJobs = 0;
        atomic<uint64_t> skippedJobs = 0;
        atomic<uint64_t> finishedJobs = 0;
        atomic<uint64_t> timeoutJobs = 0;
        atomic<uint64_t> scheduledTypeCount[(unsigned long) PropagationType::CK_NUM_TYPES] = {0};
        shared_ptr<KnownResults> knownResults;
        WorkerPool<shared_ptr<PPCheckInput>, PPCheckInputTag, shared_ptr<PPCheckOutput>, PPCheckOutputTag,
                SCD_THREADS * 2, SCD_THREADS * 2, PathPairChecker> wp;

        const static string propagationTypeStr[(unsigned long) PropagationType::CK_NUM_TYPES];

    public:
        PathPairChecker(const shared_ptr<KnownResults> &knownResults, const shared_ptr<PPCheckInputQ> &inputQ,
                        const shared_ptr<PPCheckOutputQ> &outputQ);

        bool checkingWorkerImpl(const shared_ptr<SideChannelPropagation> &input);

        const static shared_ptr<PPCheckInput> killSignal;

        virtual ~PathPairChecker();
    };
}

#endif //SCDETECTOR2_PATHPAIRCHECKER_H
