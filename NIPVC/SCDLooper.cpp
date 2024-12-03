#include "SCDLooper.h"

#include <utility>
#include "Utils.h"

using namespace std;
using namespace SCDetector;

// Timeout in seconds
void SCDLooper::looper() {
    log("SCDLooper::looper() started.");
    // Bootstrap using init secrets
    // Note here we can allow starting from the attacker side but we didn't do that for now. See notes in ResultPrinter.cpp.
    for (const auto &sym: Global::initSecrets) {
        uint8_t owner;
        owner = getOwner(OWNER_VICTIM);
        checkedSecret[owner].insert(sym);
        snfInputQ->putOneClass(make_shared<SNFInput>(sym, owner));
    }
    while (true) {
        // Process findings
        const auto &propagation = ppCheckerOutputQ->get();
        if (propagation == SideChannelPropagation::dummyProp) {
            break;
        }
        const auto &toSymbol = propagation->to;
        // Note known results already updated in Path pair checker
        // In NO_MED_TO_MED mode, med is only allowed to propagate to output. No need to double check like below.
#ifndef NO_MED_TO_MED
        // If one already propagates from med to output, there is no need to check this med again
        if (propagation->owner == getOwner(OWNER_ATTACKER) && toSymbol == Symbol::outputSymbol) {
            for (const auto &pAddrSym: *symbols) {
                knownResults->compareAndExchangePropagationStatus(propagation->owner, pAddrSym.second,
                                                                  Symbol::outputSymbol,
                                                                  KnownResults::PropagationStatus::NOT_FOUND,
                                                                  KnownResults::PropagationStatus::DISALLOWED);
            }
        }
#endif
        // Add sec name, send it to snFinder
        if (!checkedSecret[propagation->owner].contains(toSymbol)) {
            checkedSecret[propagation->owner].insert(toSymbol);
            for (auto &pOwnerHead: *fkgHead) {
                snfInputQ->putOneClass(make_shared<SNFInput>(toSymbol, pOwnerHead.first));
            }
        }
        // Send result to output
        auto resultPrinterInput = ResultPrinter::Input(propagation);
//        stringstream ss;
//        ss << "Send result of " << *propagation->from << "->" << *propagation->to << " to result printer.";
//        log(ss.str());
        resultPrinter->addJob(resultPrinterInput);
    }
}


uint8_t SCDLooper::getOwner(uint8_t desiredOwner) {
    return Global::oneOwner ? fkgHead->begin()->first : desiredOwner;
}

SCDLooper::SCDLooper(uint64_t timeout, string detailOutputDir, string binaryImageFile,
                     const shared_ptr<Fkid2GWS> &fkid2Gws, const shared_ptr<Symbols> &symbols,
                     const shared_ptr<Fkid2Fkp> &fkid2Fkp,
                     const shared_ptr<unordered_map<uint8_t, DirectPropagationMap>> &directPropagationMap,
                     const shared_ptr<FkgHeads> &fkgHead,
                     const unordered_map<PPGenInputTag, uint64_t, boost::hash<PPGenInputTag>> &ppGenInputChances,
                     const unordered_map<PPCheckInputTag, uint64_t, boost::hash<PPCheckInputTag>> &ppCheckInputChances,
                     const shared_ptr<ResultPrinterRet> &lastResultPrinterRet) : symbols(symbols), fkgHead(fkgHead),
                                                                                 knownResults(make_shared<KnownResults>(
                                                                                         fkgHead, symbols)),
                                                                                 snfInputQ(make_shared<SNFInputQ>()),
                                                                                 snfOutputQ(make_shared<SNFOutputQ>(
                                                                                         ppGenInputChances)),
                                                                                 ppGenInputQ(snfOutputQ), ppGenOutputQ(
                make_shared<PPGenOutputQ>(/*ppCheckInputChances*/)), ppCheckerInputQ(ppGenOutputQ), ppCheckerOutputQ(
                make_shared<PPCheckOutputQ>()), secNodeFinder(
                make_shared<SecNodeFinder>(knownResults, fkgHead, snfInputQ, snfOutputQ)), pathPairChecker(
                make_shared<PathPairChecker>(knownResults, ppCheckerInputQ, ppCheckerOutputQ)), partialPathGenerator(
                make_shared<PartialPathGenerator>(symbols, fkid2Gws, directPropagationMap, knownResults, fkid2Fkp,
                                                  ppGenInputQ, ppGenOutputQ, ppCheckerOutputQ,
                                                  nullptr, /*pathPairChecker,*/!!lastResultPrinterRet)), resultPrinter(
                make_shared<ResultPrinter>(std::move(detailOutputDir), std::move(binaryImageFile),
                                           !!lastResultPrinterRet)) {
    if (fkgHead->size() == 1) {
        Global::oneOwner = true;
    } else {
        Global::oneOwner = false;
    }
    log("SCDLooper: Global::oneOwner = " + to_string(Global::oneOwner));
    // Init known results
    // 1. Self propagation is always not allowed
    for (const auto &pStrSym: *symbols) {
        for (const auto &pOwnerHeads: *fkgHead) {
            knownResults->setPropagationStatus(pOwnerHeads.first, pStrSym.second, pStrSym.second,
                                               KnownResults::PropagationStatus::DISALLOWED);
        }
    }
    // 2. No output propagation to others
    for (const auto &pOwnerHeads: *fkgHead) {
        knownResults->addDisallowedFrom(Symbol::outputSymbol, pOwnerHeads.first);
    }
    // 3. To init secret is not allowed, including one init to another
    for (const auto &pOwnerHeads: *fkgHead) {
        for (const auto &sym: Global::initSecrets) {
            knownResults->addDisallowedTo(sym, pOwnerHeads.first);
        }
    }
    // 4. Anything to end is not allowed for victim propagation
    if (!Global::oneOwner) {
        knownResults->addDisallowedTo(Symbol::outputSymbol, OWNER_VICTIM);
    }
    // 5. Med to med is not allowed in NO_MED_TO_MED
#ifdef NO_MED_TO_MED
    for (const auto &pOwnerHeads: *fkgHead) {
        for (const auto &pStrSym0: *symbols) {
            if (pStrSym0.second != Symbol::outputSymbol && !Global::initSecrets.contains(pStrSym0.second)) {
                for (const auto &pStrSym1: *symbols) {
                    if (pStrSym1.second != Symbol::outputSymbol && !Global::initSecrets.contains(pStrSym1.second)) {
                        knownResults->setPropagationStatus(pOwnerHeads.first, pStrSym0.second, pStrSym1.second,
                                                           KnownResults::PropagationStatus::DISALLOWED);
                    }
                }
            }
        }
    }
    // 6. Only provided shared variables are allowed
    // TODO: adjust this when NO_MED_TO_MED is not set
    if (lastResultPrinterRet) {
        uint64_t allowedSymbolPairs = 0;
        const auto &initSecSharedVarsMap = get<1>(*lastResultPrinterRet);
        // Build common shared var
        unordered_set<shared_ptr<Symbol>> commonSharedVar;
        for (const auto &pInitSecSharedVarSet: *initSecSharedVarsMap) {
            commonSharedVar.insert(pInitSecSharedVarSet.second.begin(), pInitSecSharedVarSet.second.end());
        }
        for (const auto &pOwnerHeads: *fkgHead) {
            for (const auto &pStrSym0: *symbols) {
                for (const auto &pStrSym1: *symbols) {
                    if (!((pOwnerHeads.first == OWNER_VICTIM || Global::oneOwner) &&
                          initSecSharedVarsMap->contains(pStrSym0.second) &&
                          initSecSharedVarsMap->at(pStrSym0.second).contains(pStrSym1.second)) &&
                        !((pOwnerHeads.first == OWNER_ATTACKER || Global::oneOwner) &&
                          commonSharedVar.contains(pStrSym0.second) && pStrSym1.second == Symbol::outputSymbol)) {
                        knownResults->setPropagationStatus(pOwnerHeads.first, pStrSym0.second, pStrSym1.second,
                                                           KnownResults::PropagationStatus::DISALLOWED);
                    } else {
                        // Each shared var should have two allowed symbol pairs: init->sec, sec->out
                        allowedSymbolPairs += 1;
                    }
                }
            }
        }
        log("SCDLooper with solver allowed " + to_string(allowedSymbolPairs) + " potential symbol pairs.");
    }
#endif
    // Looper thread
    looperThread = thread(&SCDLooper::looper, this);
    monitorThread = thread(&SCDLooper::monitor, this, timeout);
}

void SCDLooper::monitor(uint64_t timeout) {
    auto startTime = chrono::system_clock::now();
    uint finishedConfirm = 0;
    while (true) {
        elapscedTime = chrono::system_clock::to_time_t(chrono::system_clock::now()) -
                       chrono::system_clock::to_time_t(startTime);
        if ((elapscedTime > timeout && timeout > 0) ||
            (!secNodeFinder->workingCount && !partialPathGenerator->workingCount && !pathPairChecker->workingCount)) {
            finishedConfirm++;
        } else {
            finishedConfirm = 0;
        }
        if (finishedConfirm == 2) {
            log("SCDLooper::looper() finished in " + to_string(elapscedTime) + "s.");
            // Ask sub threads to exit
            for (auto i = 0; i < SCD_THREADS; i++) {
                auto ppGenKill = PartialPathGenerator::killSignal;
                ppGenInputQ->put(make_tuple(symbols->begin()->second, fkgHead->begin()->first), std::move(ppGenKill));
                auto ppCheckKill = PathPairChecker::killSignal;
                ppCheckerInputQ->putOneClass(std::move(ppCheckKill));
                auto snFinderKill = SecNodeFinder::killSignal;
                snfInputQ->putOneClass(std::move(snFinderKill));
            }
            // Ask result printer to exit
            resultPrinterRet = resultPrinter->terminate();
            // Ask looper to exit
            auto dummyProp = SideChannelPropagation::dummyProp;
            ppCheckerOutputQ->putOneClass(std::move(dummyProp));
            break;
        } else {
            sleep(5);
        }
    }
}

SCDLooperRet SCDLooper::join() {
    looperThread.join();
    monitorThread.join();
    return {elapscedTime, make_shared<ResultPrinterRet>(resultPrinterRet)};
}
