#ifndef SCDETECTOR2_WORKERPOOL_H
#define SCDETECTOR2_WORKERPOOL_H

#include <thread>
#include <cassert>
#include <atomic>
#include <utility>
#include "GlobalVariables.h"
#include "ProgressPrinter.h"
#include "SyncQ.h"
#include <unistd.h>

using namespace std;
namespace SCDetector {
    template<class InputType, class InputTag, class OutputType, class OutputTag, size_t InputSize, size_t OutputSize, class WorkerClass>
    class WorkerPool {
    private:
        thread threads[SCD_THREADS];
        string name;

    public:
        WorkerPool(void (WorkerClass::*workFunc)(const shared_ptr<FairSyncMultiQ<InputType, InputTag, InputSize>> &,
                                                 const shared_ptr<FairSyncMultiQ<OutputType, OutputTag, OutputSize>> &),
                   const shared_ptr<FairSyncMultiQ<InputType, InputTag, InputSize>> &inputQ,
                   const shared_ptr<FairSyncMultiQ<OutputType, OutputTag, OutputSize>> &outputQ, WorkerClass *workerObj,
                   const string &name) : name(name) {
            // Init threads
            for (auto &t: threads) {
                t = std::thread([workerObj, inputQ, outputQ, workFunc] {
                    (workerObj->*workFunc)(inputQ, outputQ);
                });
            }
            // Log
            ProgressPrinter::getPrinter()->addKey(LOGNAME_WORKERPOOL_UNFINISHED_JOBS + name, &inputQ->totalBufferLen,
                                                  &inputQ->processedElements);
        }

        // Note user is responsible for terminating the thread
        ~WorkerPool() {
            ProgressPrinter::getPrinter()->removeKey(LOGNAME_WORKERPOOL_UNFINISHED_JOBS + name);
            for (auto &t: threads) {
                t.join();
            }
        }
    };
}
#endif //SCDETECTOR2_WORKERPOOL_H
