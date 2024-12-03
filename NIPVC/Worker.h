#ifndef SCDETECTOR2_WORKER_H
#define SCDETECTOR2_WORKER_H

#include <atomic>
#include <string>

using namespace std;

namespace SCDetector {
    class Worker {
    public:
        atomic<uint64_t> workingCount = 0;
        virtual ~Worker();
    protected:
        string name;
        Worker(const string& name);
    };
}

#endif //SCDETECTOR2_WORKER_H
