#ifndef SCDETECTOR2_SCDLOOPER_H
#define SCDETECTOR2_SCDLOOPER_H

#include "SecNodeFinder.h"
#include "PartialPathGenerator.h"
#include "PathPairChecker.h"
#include "ResultPrinter.h"

using namespace std;
namespace SCDetector {
    class SCDLooper {
    private:
        void looper();

        uint8_t getOwner(uint8_t desiredOwner);

        void monitor(uint64_t timeout);

        ResultPrinterRet resultPrinterRet;
        unordered_map<uint8_t, unordered_set<shared_ptr<Symbol>>> checkedSecret;
        const shared_ptr<Symbols> symbols;
        const shared_ptr<FkgHeads> fkgHead; // owner -> head
        const shared_ptr<KnownResults> knownResults;
        const shared_ptr<SNFInputQ> snfInputQ;
        const shared_ptr<SNFOutputQ> snfOutputQ;
        const shared_ptr<PPGenInputQ> ppGenInputQ;
        const shared_ptr<PPGenOutputQ> ppGenOutputQ;
        const shared_ptr<PPCheckInputQ> ppCheckerInputQ;
        const shared_ptr<PPCheckOutputQ> ppCheckerOutputQ;
        const shared_ptr<SecNodeFinder> secNodeFinder;
        const shared_ptr<PathPairChecker> pathPairChecker;
        // Checker is needed first if ppGen is in sync mode
        const shared_ptr<PartialPathGenerator> partialPathGenerator;
        const shared_ptr<ResultPrinter> resultPrinter;
        uint64_t elapscedTime = 0;
        thread looperThread;
        thread monitorThread;


    public:
        SCDLooper(uint64_t timeout, string detailOutputDir, string binaryImageFile,
                  const shared_ptr<Fkid2GWS> &fkid2Gws, const shared_ptr<Symbols> &symbols,
                  const shared_ptr<Fkid2Fkp> &fkid2Fkp,
                  const shared_ptr<unordered_map<uint8_t, DirectPropagationMap>> &directPropagationMap,
                  const shared_ptr<FkgHeads> &fkgHead,
                  const unordered_map<PPGenInputTag, uint64_t, boost::hash<PPGenInputTag>> &ppGenInputChances,
                  const unordered_map<PPCheckInputTag, uint64_t, boost::hash<PPCheckInputTag>> &ppCheckInputChances,
                  const shared_ptr<ResultPrinterRet>& lastResultPrinterRet);

        SCDLooperRet join();
    };

}

#endif //SCDETECTOR2_SCDLOOPER_H
