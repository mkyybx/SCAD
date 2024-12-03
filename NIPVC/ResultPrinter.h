#ifndef SCDETECTOR2_RESULTPRINTER_H
#define SCDETECTOR2_RESULTPRINTER_H

#include "BasicType.h"
#include "WorkerPool.h"

using namespace std;
namespace SCDetector {
    class ResultPrinter {
    public:
        class Input {
        private:
            friend class ResultPrinter;

            shared_ptr<SideChannelPropagation> propagation;
        public:
            explicit Input(const shared_ptr<SideChannelPropagation> &propagation);

            Input() = default;
        };

        ResultPrinter(string detailOutputDir, string binaryImageFile, bool outputModel);

        void addJob(Input &input);

        uint64_t getUnfinishedJobCount();

        virtual ~ResultPrinter();

        ResultPrinterRet terminate();

        void requestExit();

    private:
        void resultPrinter();

        static HighOrderPropagationMap buildPropagationOnPrev(const Prev &prev, const shared_ptr<Symbol> &initSymbol,
                                                              const PropagationMap &localPropagationMap);

        static shared_ptr<SideChannelPropagation> getAPropagation(const SideChannelPropagations &scp);

        void outputResultsToFile();

        SyncQ<Input, SIZE_MAX> inputQ;
        atomic<uint64_t> oneSidePropagation = 0;
        atomic<uint64_t> twoSidesPropagation = 0;
        atomic<uint64_t> directPropagation = 0;
        atomic<uint64_t> totalPropagation = 0;
        atomic<uint64_t> unfinishedJobsCount = 0;
        string detailOutputDir;
        string binaryImageFile;
        unordered_map<uint8_t, PropagationMap> propagationMap;
        shared_ptr<unordered_map<uint8_t, HighOrderPropagationMap>> shortestPropPaths;
        shared_ptr<unordered_map<shared_ptr<Symbol>, unordered_set<shared_ptr<Symbol>>>> sharedSymbols; // Per init secret
        thread printerThread;
        bool outputModel;
        bool shouldExit = false;
    };
}


#endif //SCDETECTOR2_RESULTPRINTER_H
