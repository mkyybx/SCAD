#ifndef SCDETECTOR2_SECNODEFINDER_H
#define SCDETECTOR2_SECNODEFINDER_H

#include "Using.h"
#include <unordered_set>
#include "WorkerPool.h"
#include "KnownResults.h"
#include "Worker.h"

using namespace std;
namespace SCDetector {
    class SecNodeFinder : public Worker {
    private:
        shared_ptr<KnownResults> knownResults;
        const shared_ptr<FkgHeads> fkgHead;
        unordered_map<uint8_t, atomic<uint64_t>> secNameChecked;
        mutex parentPartialPathMapLock;
        unordered_map<shared_ptr<ForkPoint>, shared_ptr<PartialPath>> parentPartialPathMap;
        WorkerPool<shared_ptr<SNFInput>, SNFInputTag, shared_ptr<SNFOutput>, SNFOutputTag,
                SCD_THREADS * 2, SCD_THREADS * 2, SecNodeFinder> wp;

        void secNodeFinder(const shared_ptr<SNFInputQ> &inputQ, const shared_ptr<SNFOutputQ> &outputQ);

        // Returns if it's empty. Empty = true
        bool findSecNode(const shared_ptr<ForkPoint> &node, const shared_ptr<Symbol> &secSym,
                         const shared_ptr<SNFOutputQ> &outputQ, const uint8_t &owner, uint64_t& secNodeCount);

    public:
        SecNodeFinder(const shared_ptr<KnownResults> &knownResults, const shared_ptr<FkgHeads> &fkgHead,
                      const shared_ptr<SNFInputQ> &inputQ, const shared_ptr<SNFOutputQ> &outputQ);

        const static shared_ptr<SNFInput> killSignal;

        virtual ~SecNodeFinder();
    };
}

#endif //SCDETECTOR2_SECNODEFINDER_H
