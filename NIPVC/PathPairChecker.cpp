#include "PathPairChecker.h"
#include "SolverManager.h"
#include "ProgressPrinter.h"

using namespace std;
using namespace SCDetector;


bool PathPairChecker::checkingWorkerImpl(const shared_ptr<SideChannelPropagation> &input) {
    submittedJobs++;
    scheduledTypeCount[(unsigned long) input->propagationType]++;
    bool goodPair = false;
    // If it's direct propagation
    if (input->directPropagation) {
        finishedJobs++;
        goodPair = true;
    } else {
        assert(input->pp[0] && input->pp[1] && input->pp[0]->gw.size() == 1 && input->pp[1]->gw.size() == 1);
        if (knownResults->isPropagationAllowed(input->owner, input->from, input->to)) {
            // Get Z3 solver
            auto bundle = Global::solverManager->getSolverBundle();
            auto checkResult = input->checkSat(bundle);
            Global::solverManager->putSolverBundle(bundle);
            if (checkResult == SolverCheckResult::UNKNOWN) {
                ++timeoutJobs;
            } else {
                ++finishedJobs;
                if (checkResult == SolverCheckResult::SAT) {
                    goodPair = true;
                }
            }
        } else {
            ++skippedJobs;
        }
//#ifdef NO_MED_TO_MED
//        knownResults->reducePartialPathCount(input);
//#endif
    }
    return goodPair;
}

void
PathPairChecker::checkingWorker(const shared_ptr<PPCheckInputQ> &inputQ, const shared_ptr<PPCheckOutputQ> &outputQ) {
    while (true) {
        auto &&input = inputQ->get();
        if (input == killSignal) {
            return;
        }
        workingCount++;
        for (auto &prop: *input) {
            if (checkingWorkerImpl(prop)) {
                knownResults->setPropagationStatus(prop->owner, prop->from, prop->to,
                                                   KnownResults::PropagationStatus::PROVED);
                outputQ->putOneClass(std::move(prop));
            }
        }
        workingCount--;
    }
}

PathPairChecker::PathPairChecker(const shared_ptr<KnownResults> &knownResults, const shared_ptr<PPCheckInputQ> &inputQ,
                                 const shared_ptr<PPCheckOutputQ> &outputQ) : Worker("PathPairChecker"),
                                                                              knownResults(knownResults),
                                                                              wp(&PathPairChecker::checkingWorker,
                                                                                 inputQ, outputQ, this,
                                                                                 "PathPairChecker") {
    ProgressPrinter::getPrinter()->addKey(LOGNAME_CHECKER_FINISHED, &finishedJobs, &submittedJobs);
    ProgressPrinter::getPrinter()->addKey(LOGNAME_CHECKER_TIMEOUT, &timeoutJobs, &submittedJobs);
    ProgressPrinter::getPrinter()->addKey(LOGNAME_CHECKER_SKIPPED, &skippedJobs, &submittedJobs);
    for (auto i = 0; i < (unsigned long) PropagationType::CK_NUM_TYPES; i++) {
        ProgressPrinter::getPrinter()->addKey(LOGNAME_CHECKER_TYPE + propagationTypeStr[i], &scheduledTypeCount[i],
                                              &submittedJobs);
    }
}

PathPairChecker::~PathPairChecker() {
    ProgressPrinter::getPrinter()->removeKey(LOGNAME_CHECKER_FINISHED);
    ProgressPrinter::getPrinter()->removeKey(LOGNAME_CHECKER_TIMEOUT);
    ProgressPrinter::getPrinter()->removeKey(LOGNAME_CHECKER_SKIPPED);
    for (const auto &typeStr: propagationTypeStr) {
        ProgressPrinter::getPrinter()->removeKey(LOGNAME_CHECKER_TYPE + typeStr);
    }
}


namespace SCDetector {
    const string PathPairChecker::propagationTypeStr[(unsigned long) PropagationType::CK_NUM_TYPES] = {"SEC_ONE",
                                                                                                       "SEC_TWO",
                                                                                                       "SEC_DIRECT",
                                                                                                       "MED_ONE",
                                                                                                       "MED_TWO",
                                                                                                       "MED_DIRECT",
                                                                                                       "OUT_ONE",
                                                                                                       "OUT_TWO",
                                                                                                       "OUT_DIRECT"};

    const shared_ptr<PPCheckInput> PathPairChecker::killSignal = nullptr;
}
