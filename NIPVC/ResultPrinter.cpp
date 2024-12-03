#include <sstream>
#include "ResultPrinter.h"
#include "Utils.h"
#include "ProgressPrinter.h"
#include "Dijkstra.h"
#include <fstream>
#include <utility>
#include "SolverManager.h"
#include "Using.h"

using namespace std;
using namespace SCDetector;

void ResultPrinter::resultPrinter() {
    Input dummy(nullptr);
    while (true) {
        bool foundNewProp = false;
        bool waitedOnce = false;
        uint8_t owner;
        while (true) {
            auto input = inputQ.getUnblocked(dummy);
            if (!input.propagation) {
                if (!foundNewProp) {
                    if (shouldExit) {
                        return;
                    }
                    sleep(30);
                    continue;
                } else {
                    if (!waitedOnce) {
                        waitedOnce = true;
                        sleep(30);
                        continue;
                    } else {
                        break;
                    }
                }
            }
            foundNewProp = true;
            waitedOnce = false;
            // Log the result
            stringstream ss;
            ss << "ResultPrinter: Found propagation: " << *input.propagation->from << " -> " << *input.propagation->to
               << ", type ";
            if (input.propagation->directPropagation) {
                ss << "direct, ";
                directPropagation++;
            } else if (input.propagation->pp.at(0)->gw.begin()->second == GlobalWrite::gwNoWrite ||
                       input.propagation->pp.at(1)->gw.begin()->second == GlobalWrite::gwNoWrite) {
                ss << "one side, ";
                oneSidePropagation++;
            } else {
                ss << "two sides, ";
                twoSidesPropagation++;
            }
            totalPropagation++;
            ss << "owner " << (uint) input.propagation->owner;
            log(ss.str());
            // Insert the new propagation
            auto &propagations = propagationMap[input.propagation->owner][input.propagation->from][input.propagation->to];
            propagations.propagations.push_back(input.propagation);
            if (input.propagation->directPropagation) {
                propagations.hasDirectPropagation = true;
            }
            owner = input.propagation->owner;
        }
        log("Begin building output graphs.");
        // Check for updated propagation paths
        if (Global::oneOwner) {
            for (const auto &initSymbol: Global::initSecrets) {
                // Find shared variable. Here we assume the first propagate-to is shared in case NO_MED_TO_MED is undefined.
                for (const auto &pToVecs: propagationMap[owner][initSymbol]) {
                    const auto &sharedVar = pToVecs.first;
                    // In case we directly propagate to the output symbol. This is a special case.
                    if (sharedVar == Symbol::outputSymbol) {
                        if (!(*sharedSymbols)[initSymbol].contains(sharedVar)) {
                            // Add to shared var
                            (*sharedSymbols)[initSymbol].insert(sharedVar);
                            stringstream ss;
                            ss << "ResultPrinter: Found direct output for secret " << *initSymbol;
                            log(ss.str());
                        }
                        // Update HO propagation
                        const auto &firstProp = getAPropagation(
                                pToVecs.second);    // This must exist otherwise pToVecs doesn't exist
                        (*shortestPropPaths)[owner][initSymbol][sharedVar].propagations[0] = firstProp;
                    } else {
                        // Build the second half
                        Prev prev;
                        Dijkstra<shared_ptr<Symbol>>::dijkstra(
                                *SideChannelPropagation::toDijkstraMap(propagationMap[owner]), sharedVar, prev);
                        const auto &&newHOPropMap = buildPropagationOnPrev(prev, sharedVar, propagationMap[owner]);
                        // Connect together and see if we got a new valid shared variable. newHOPropMap will be empty if shared var leads to nowhere
                        if (newHOPropMap.contains(sharedVar) &&
                            newHOPropMap.at(sharedVar).contains(Symbol::outputSymbol)) {
                            if (!(*sharedSymbols)[initSymbol].contains(sharedVar)) {
                                // Add to shared var
                                (*sharedSymbols)[initSymbol].insert(sharedVar);
                                stringstream ss;
                                ss << "ResultPrinter: Found shared var " << *sharedVar << " for secret " << *initSymbol;
                                log(ss.str());
                            }
                            // If we are shorter or new, output the new path
                            auto newLength = newHOPropMap.at(sharedVar).at(Symbol::outputSymbol).propagations.size();
                            auto curLength = (*shortestPropPaths)[owner][sharedVar][Symbol::outputSymbol].propagations.size();
                            if (newLength < curLength || curLength == 0) {
                                stringstream ss;
                                ss << "ResultPrinter: Found shorter path for shared var " << *sharedVar << ": ";
                                for (const auto &prop: newHOPropMap.at(sharedVar).at(
                                        Symbol::outputSymbol).propagations) {
                                    ss << *prop->to << " <- ";
                                }
                                ss << *sharedVar << " <- " << *initSymbol;
                                log(ss.str());
                            } else if (newLength > curLength) {
                                stringstream ss;
                                ss << "ResultPrinter: Bug found as newLength > curLength for " << *sharedVar << " -> "
                                   << *Symbol::outputSymbol;
                                log(ss.str());
                                abort();
                            }
                            // Update HO propagation
                            const auto &firstProp = getAPropagation(
                                    pToVecs.second);    // This must exist otherwise pToVecs doesn't exist
                            (*shortestPropPaths)[owner][initSymbol][sharedVar].propagations[0] = firstProp;
                            if (firstProp->directPropagation) {
                                (*shortestPropPaths)[owner][initSymbol][sharedVar].hasDirectPropagation = true;
                            }
                            (*shortestPropPaths)[owner][sharedVar] = newHOPropMap.at(sharedVar);
                        }
                    }
                }
            }
        } else {
            // TODO: We didn't consider attacker only propagation. In fact, the propagation between attacker and victim path can be interleveaving. But we don't consider it for now.
            for (const auto &initSymbol: Global::initSecrets) {
                // Find the victim part
                Prev prev;
                Dijkstra<shared_ptr<Symbol>>::dijkstra(
                        *SideChannelPropagation::toDijkstraMap(propagationMap[OWNER_VICTIM]), initSymbol, prev);
//                for (const auto& sym : prev) {
//                    stringstream ss;
//                    ss << "Prev[" << *sym.first << "]=" << *sym.second;
//                }
                auto &&victimHOPropMap = buildPropagationOnPrev(prev, initSymbol, propagationMap[OWNER_VICTIM]);
//                for (const auto& pFromToVec : victimHOPropMap) {
//                    for (const auto& pToVec : pFromToVec.second) {
//                        stringstream ss;
//                        ss << "victimHOPropMap: " << *pFromToVec.first << "->" << *pToVec.first;
//                        log(ss.str());
//                    }
//                }
                // Find the attacker part
                for (const auto &pPotentialSharedVecs: victimHOPropMap[initSymbol]) {
                    const auto &potentialSV = pPotentialSharedVecs.first;
                    Prev prev;
                    Dijkstra<shared_ptr<Symbol>>::dijkstra(
                            *SideChannelPropagation::toDijkstraMap(propagationMap[OWNER_ATTACKER]), potentialSV, prev);
                    const auto &&attackerHOPropMap = buildPropagationOnPrev(prev, potentialSV,
                                                                            propagationMap[OWNER_ATTACKER]);
//                    for (const auto& pFromToVec : attackerHOPropMap) {
//                        for (const auto &pToVec: pFromToVec.second) {
//                            stringstream ss;
//                            ss << "attackerHOPropMap: " << *pFromToVec.first << "->" << *pToVec.first;
//                            log(ss.str());
//                        }
//                    }
                    // Connect and see if we get any new shared variable
                    if (attackerHOPropMap.contains(potentialSV) &&
                        attackerHOPropMap.at(potentialSV).contains(Symbol::outputSymbol)) {
                        // We got new output
                        if (!(*sharedSymbols)[initSymbol].contains(potentialSV)) {
                            // Add to shared var
                            (*sharedSymbols)[initSymbol].insert(potentialSV);
                            stringstream ss;
                            ss << "ResultPrinter: Found shared var " << *potentialSV << " for secret " << *initSymbol;
                            log(ss.str());
                        }
                        // If we are shorter or new, output the new path
                        auto newLength = victimHOPropMap.at(initSymbol).at(potentialSV).propagations.size() +
                                         attackerHOPropMap.at(potentialSV).at(Symbol::outputSymbol).propagations.size();
                        auto victimLength = (*shortestPropPaths)[OWNER_VICTIM][initSymbol][potentialSV].propagations.size();
                        auto attackerLength = (*shortestPropPaths)[OWNER_ATTACKER][potentialSV][Symbol::outputSymbol].propagations.size();
                        if (newLength < victimLength + attackerLength || victimLength == 0 || attackerLength == 0) {
                            stringstream ss;
                            ss << "ResultPrinter: Found shorter path for shared var " << *potentialSV << ": ";
                            for (const auto &attackerProp: attackerHOPropMap.at(potentialSV).at(
                                    Symbol::outputSymbol).propagations) {
                                ss << *attackerProp->to << " <- ";
                            }
                            for (const auto &victimProp: victimHOPropMap.at(initSymbol).at(potentialSV).propagations) {
                                ss << *victimProp->to << " <- ";
                            }
                            ss << *initSymbol;
                            log(ss.str());
                        } else if (newLength > victimLength + attackerLength) {
                            stringstream ss;
                            ss << "ResultPrinter: Bug found as newLength > victimLength + attackerLength for "
                               << *initSymbol << " -> " << *potentialSV << " -> " << *Symbol::outputSymbol;
                            log(ss.str());
                            abort();
                        }
                        // Update attacker HO propagation
                        (*shortestPropPaths)[OWNER_ATTACKER][potentialSV] = attackerHOPropMap.at(potentialSV);
                    }
                }
                // Update victim HO propagation
                if (!victimHOPropMap.at(initSymbol).empty()) {
                    (*shortestPropPaths)[OWNER_VICTIM][initSymbol] = victimHOPropMap.at(initSymbol);
                }
            }
        }
        log("End building output graphs.");
        // Output details
        log("Begin output traces.");
        outputResultsToFile();
        unfinishedJobsCount--;
        log("End output traces.");
    }
}

HighOrderPropagationMap ResultPrinter::buildPropagationOnPrev(const Prev &prev, const shared_ptr<Symbol> &initSymbol,
                                                              const PropagationMap &localPropagationMap) {
    HighOrderPropagationMap ret;
    // Any symbol in the prev must have a path to initSecrets.
    for (const auto &pCurFrom: prev) {
        auto cur = pCurFrom.first;
        const auto &toSymbol = pCurFrom.first;
        while (cur != initSymbol) {
            const auto &curPropagations = localPropagationMap.at(prev.at(cur)).at(cur);
            // The propagationsStatus is in reverse sequence.
            ret[initSymbol][toSymbol].propagations.push_back(getAPropagation(curPropagations));
            cur = prev.at(cur);
        }
    }
    return ret;
}


shared_ptr<SideChannelPropagation> ResultPrinter::getAPropagation(const SideChannelPropagations &scp) {
    auto it = scp.propagations.begin();
    // Prioritize direct propagation
    if (scp.hasDirectPropagation) {
        for (it = scp.propagations.begin(); it < scp.propagations.end(); it++) {
            if ((*it)->directPropagation) {
                break;
            }
        }
    } else {
        // Prioritize one side propagation
        for (it = scp.propagations.begin(); it < scp.propagations.end(); it++) {
            if ((*it)->pp.at(0)->gw.begin()->second == GlobalWrite::gwNoWrite ||
                (*it)->pp.at(1)->gw.begin()->second == GlobalWrite::gwNoWrite) {
                break;
            }
        }
        if (it == scp.propagations.end()) {
            it = scp.propagations.begin();
        }
    }
    return *it;
}

void ResultPrinter::outputResultsToFile() {
    vector<thread> workerThreads;
    for (const auto &pInitSecSharedVars: *sharedSymbols) {
        const auto &initSymbol = pInitSecSharedVars.first;
        for (const auto &sharedVar: pInitSecSharedVars.second) {
            workerThreads.emplace_back([this, sharedVar, initSymbol] {
                // Open file
                string fileName = detailOutputDir + "/" + Utils::hexval(sharedVar->addr) + "_from_" +
                                  Utils::hexval(initSymbol->addr) + (outputModel ? "_with_model" : "") + ".txt";
                ofstream ofs(fileName);
                if (!ofs.is_open()) {
                    log("outputResultsToFile: File " + fileName + " cannot be opened!");
                } else {
                    // 1. Output overall propagation path
                    vector<shared_ptr<SideChannelPropagation>> hoProp;
                    // Note if there is a shared var, the related propagation must exist
                    // Shared var -> output
                    for (const auto &propagation: (Global::oneOwner ? shortestPropPaths->begin()->second
                                                                    : shortestPropPaths->at(OWNER_ATTACKER)).at(
                            sharedVar).at(Symbol::outputSymbol).propagations) {
                        hoProp.push_back(propagation);
                    }
                    // Init -> shared var
                    for (const auto &propagation: (Global::oneOwner ? shortestPropPaths->begin()->second
                                                                    : shortestPropPaths->at(OWNER_VICTIM)).at(
                            initSymbol).at(
                            sharedVar).propagations) {
                        hoProp.push_back(propagation);
                    }
                    std::reverse(hoProp.begin(), hoProp.end());
                    // Output
                    for (const auto &propagation: hoProp) {
                        ofs << *propagation->from << " ->(" << (uint) propagation->owner << ") ";
                    }
                    ofs << *Symbol::outputSymbol << "\n";
                    for (const auto &propagation: hoProp) {
                        // 2. Output execution trace
                        string type;
                        stringstream executionTrace;
                        if (propagation->directPropagation) {
                            type = "Direct";
                            executionTrace << Utils::getExecutionTrace(propagation->directPropagation->bottomNode,
                                                                       propagation->directPropagation->secNode,
                                                                       binaryImageFile);
                            executionTrace << "\nGlobal write: "
                                           << *propagation->directPropagation->gwUsedForModelQuery;
                        } else {
                            type = "Indirect";
                            for (auto i = 0; i < 2; i++) {
                                executionTrace << "\nGlobal write " << (i == 0 ? "L" : "R") << ": "
                                               << *propagation->pp.at(i)->gw.begin()->second;
                            }
                            for (auto i = 0; i < 2; i++) {
                                executionTrace << "\nPath " << (i == 0 ? "L" : "R") << ": "
                                               << Utils::getExecutionTrace(propagation->pp.at(i)->bottom,
                                                                           propagation->pp.at(i)->top, binaryImageFile);
                            }
                        }
                        ofs << "Execution trace for " << *propagation->from << " -> " << *propagation->to << " ("
                            << type
                            << "):\n" << executionTrace.str() << "\n";
                        if (outputModel) {
                            // 3. Output model query
                            auto bundle = Global::solverManager->getSolverBundle();
                            auto res = propagation->buildModel(bundle);
                            ofs << "Model Query:\n" << Global::solverManager->dumpSMT2(bundle) << "\n";
                            // 4. Output model
                            if (res == SolverCheckResult::SAT) {
                                ofs << "Model:\n" << Global::solverManager->dumpModel(bundle) << "\n";
                            } else {
                                ofs << "Get model timeout\n";
                            }
                            ofs << "\n";
                            Global::solverManager->putSolverBundle(bundle);
                        }
                    }
                    ofs.close();
                }
            });
        }
    }
    for (auto &t: workerThreads) {
        t.join();
    }
}

void ResultPrinter::addJob(ResultPrinter::Input &input) {
    inputQ.put(std::move(input));
    unfinishedJobsCount++;
}

ResultPrinter::ResultPrinter(string detailOutputDir, string binaryImageFile, bool outputModel) : detailOutputDir(
        std::move(detailOutputDir)), binaryImageFile(std::move(binaryImageFile)), outputModel(outputModel),
                                                                                                 shortestPropPaths(
                                                                                                         make_shared<unordered_map<uint8_t, HighOrderPropagationMap>>()),
                                                                                                 sharedSymbols(
                                                                                                         make_shared<unordered_map<shared_ptr<Symbol>, unordered_set<shared_ptr<Symbol>>>>()) {
    printerThread = thread(&ResultPrinter::resultPrinter, this);
    // Log
    ProgressPrinter::getPrinter()->addKey(LOGNAME_PRINTER_DIRECTPROPAGATION, &directPropagation, &totalPropagation);
    ProgressPrinter::getPrinter()->addKey(LOGNAME_PRINTER_ONESIDEPROPAGATION, &oneSidePropagation, &totalPropagation);
    ProgressPrinter::getPrinter()->addKey(LOGNAME_PRINTER_TWOSIDESPROPAGATION, &twoSidesPropagation, &totalPropagation);
}

uint64_t ResultPrinter::getUnfinishedJobCount() {
    return unfinishedJobsCount;
}

ResultPrinter::~ResultPrinter() {
    ProgressPrinter::getPrinter()->removeKey(LOGNAME_PRINTER_DIRECTPROPAGATION);
    ProgressPrinter::getPrinter()->removeKey(LOGNAME_PRINTER_ONESIDEPROPAGATION);
    ProgressPrinter::getPrinter()->removeKey(LOGNAME_PRINTER_TWOSIDESPROPAGATION);
    if (printerThread.joinable()) {
        printerThread.join();
    }
}

ResultPrinterRet ResultPrinter::terminate() {
    shouldExit = true;
    if (printerThread.joinable()) {
        printerThread.join();
    }
    return {shortestPropPaths, sharedSymbols};
}

void ResultPrinter::requestExit() {
    shouldExit = true;
}

ResultPrinter::Input::Input(const shared_ptr<SideChannelPropagation> &propagation) : propagation(propagation) {}
