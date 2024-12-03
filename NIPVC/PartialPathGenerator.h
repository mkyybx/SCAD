#ifndef SCDETECTOR2_PARTIALPATHGENERATOR_H
#define SCDETECTOR2_PARTIALPATHGENERATOR_H

#include "BasicType.h"
#include "KnownResults.h"
#include "WorkerPool.h"
#include "Using.h"
#include "PathPairChecker.h"
#include "Worker.h"

using namespace std;
namespace SCDetector {
    class PPGenInput {
    public:
        PPGenInput(const shared_ptr<ForkPoint> &node, const shared_ptr<Symbol> &secSymbol, uint8_t owner,
                   const shared_ptr<PartialPath> &commonPartialPath);

        shared_ptr<ForkPoint> node;
        shared_ptr<Symbol> secSymbol;
        uint8_t owner;
        shared_ptr<PartialPath> commonPartialPath;
    };

    class PartialPathGenerator : public Worker {
    public:
        PartialPathGenerator(const shared_ptr<Symbols> &symbols, const shared_ptr<Fkid2GWS> &fkid2Gws,
                             const shared_ptr<unordered_map<uint8_t, DirectPropagationMap>> &directPropagationMap,
                             const shared_ptr<KnownResults> &knownResults, const shared_ptr<Fkid2Fkp> &fkid2Fkp,
                             const shared_ptr<PPGenInputQ> &inputQ, const shared_ptr<PPGenOutputQ> &outputQ,
                             const shared_ptr<PPCheckOutputQ> &ppCheckOutputQ,
                             const shared_ptr<PathPairChecker> &pathPairChecker, bool runSolver);

        static void setBufferMaxSize(uint64_t bufferMaxSize);

        const static shared_ptr<PPGenInput> killSignal; // null signals the termination

        virtual ~PartialPathGenerator() = default;

    private:
        // Sync mode
        const shared_ptr<PPCheckOutputQ> ppCheckOutputQ;
        const shared_ptr<PathPairChecker> pathPairChecker;

        const shared_ptr<Symbols> symbols;
        const shared_ptr<Fkid2GWS> fkid2GWS;
        const shared_ptr<unordered_map<uint8_t, DirectPropagationMap>> directPropagationMap;
        shared_ptr<KnownResults> knownResults;
        const shared_ptr<Fkid2Fkp> fkid2fkp;
        const bool runSolver;

        static uint64_t bufferMaxSize;

        WorkerPool<shared_ptr<PPGenInput>, PPGenInputTag, shared_ptr<PPGenOutput>, PPGenOutputTag,
                SCD_THREADS * 2, SCD_THREADS * 2, PartialPathGenerator> PPGwp;

        void partialPathGenerator(const shared_ptr<PPGenInputQ> &inputQ, const shared_ptr<PPGenOutputQ> &outputQ);

        FPPRet findPartialPath(const shared_ptr<ForkPoint> &node, FPPRes &result, const FPPReq &request,
                               const shared_ptr<ForkPoint> &topNode, const string &secName);

        void collectPossibleWriteToAddr(const shared_ptr<ForkPoint> &node, unordered_set<uint64_t> &result);
    };

}

#endif //SCDETECTOR2_PARTIALPATHGENERATOR_H
