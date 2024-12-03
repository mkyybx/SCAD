#include "KnownResults.h"
#include "ProgressPrinter.h"

using namespace std;
using namespace SCDetector;

void KnownResults::setPropagationStatus(uint8_t owner, const shared_ptr<Symbol> &from, const shared_ptr<Symbol> &to,
                                        PropagationStatus status) {
    propagationsStatus.at(owner).at(from).at(to) = status;
}

KnownResults::PropagationStatus
KnownResults::getPropagationStatus(uint8_t owner, const shared_ptr<Symbol> &from, const shared_ptr<Symbol> &to) {
    return propagationsStatus.at(owner).at(from).at(to);
}

bool KnownResults::compareAndExchangePropagationStatus(uint8_t owner, const shared_ptr<Symbol> &from,
                                                       const shared_ptr<Symbol> &to,
                                                       KnownResults::PropagationStatus expected,
                                                       KnownResults::PropagationStatus desired) {
    return propagationsStatus.at(owner).at(from).at(to).compare_exchange_strong(expected, desired);
}


KnownResults::KnownResults(const shared_ptr<FkgHeads> &fkgHead, const shared_ptr<Symbols> &symbols) : fkgHead(fkgHead),
                                                                                                      symbols(symbols),
                                                                                                      validSymbols(
                                                                                                              symbols->size() -
                                                                                                              1) {
    // Init status maps
    for (const auto &pOwnerHead: *fkgHead) {
        for (const auto &pAddrSym0: *symbols) {
            for (const auto &pAddrSym1: *symbols) {
                propagationsStatus[pOwnerHead.first][pAddrSym0.second][pAddrSym1.second] = PropagationStatus::NOT_FOUND;
            }
        }
    }
#ifdef NO_MED_TO_MED
    /*
    // Log
    ProgressPrinter::getPrinter()->addKey(LOGNAME_KNOWNRESULTS_ESTIMATION_VALID_SYMS, &validSymbols,
                                          &Global::totalSymbols);
    // Pre-allocate maps to avoid locking
    for (const auto &pStrSym0: *symbols) {
        secNodeCountPerSymbol[pStrSym0.second] = UINT64_MAX;
        checkedSecNodeCountPerSymbol[pStrSym0.second] = UINT64_MAX;
        for (const auto &pStrSym1: *symbols) {
            fromToTotalSCPPCount[pStrSym0.second][pStrSym1.second] = UINT64_MAX;
            fromToCheckedSCPPCount[pStrSym0.second][pStrSym1.second] = UINT64_MAX;
        }
    }
     */
#endif
}

void KnownResults::addDisallowedFrom(const shared_ptr<Symbol> &from, uint8_t owner) {
    for (const auto &pAddrSym: *symbols) {
        compareAndExchangePropagationStatus(owner, from, pAddrSym.second, PropagationStatus::NOT_FOUND,
                                            PropagationStatus::DISALLOWED);
    }
}

void KnownResults::addDisallowedTo(const shared_ptr<Symbol> &to, uint8_t owner) {
    for (const auto &pAddrSym: *symbols) {
        compareAndExchangePropagationStatus(owner, pAddrSym.second, to, PropagationStatus::NOT_FOUND,
                                            PropagationStatus::DISALLOWED);
    }
}

bool KnownResults::isPropagationAllowed(uint8_t owner, const shared_ptr<Symbol> &from, const shared_ptr<Symbol> &to) {
    return getPropagationStatus(owner, from, to) == PropagationStatus::NOT_FOUND;
}

#ifdef NO_MED_TO_MED
/*
// TODO: This is buggy. It's possible at some time count==checkedCount when producer didn't finish production but consumer consumed all already.
void KnownResults::addSecNodesCount(const shared_ptr<Symbol> &secSymbol) {
    if (secNodeCountPerSymbol.at(secSymbol) == UINT64_MAX) {
        secNodeCountPerSymbol.at(secSymbol) = 0;
    }
    secNodeCountPerSymbol.at(secSymbol) += 1;
}

void KnownResults::reduceSecNodesCount(const shared_ptr<Symbol> &secSymbol) {
    assert(secNodeCountPerSymbol.at(secSymbol) > 0 && secNodeCountPerSymbol.at(secSymbol) != UINT64_MAX);
    if (checkedSecNodeCountPerSymbol.at(secSymbol) == UINT64_MAX) {
        checkedSecNodeCountPerSymbol.at(secSymbol) = 0;
    }
    if (++checkedSecNodeCountPerSymbol.at(secSymbol) == secNodeCountPerSymbol.at(secSymbol)) {
        checkLevel1Impossible(secSymbol);
    }
}

void
KnownResults::addPartialPathCount(const shared_ptr<Symbol> &from, const shared_ptr<Symbol> &to) {
    assert(secNodeCountPerSymbol.at(from) > 0 && secNodeCountPerSymbol.at(from) != UINT64_MAX);
//    if (to->addrStr == "0xffffffff8212331c") {
//        log("123");
//    }
    if (fromToTotalSCPPCount.at(from).at(to) == UINT64_MAX) {
        fromToTotalSCPPCount.at(from).at(to) = 0;
    }
    fromToTotalSCPPCount.at(from).at(to) += 1;
}

void KnownResults::checkLevel1Impossible(const shared_ptr<Symbol> &secSymbol) {
    return;
    auto owner = fkgHead->begin()->first;   // One owner case
    // Finished checking all nodes of a sec name. Determine the reachability
    // Disallow from med to out
    if (Global::initSecrets.contains(secSymbol)) {
        if (!Global::oneOwner) {
            owner = OWNER_VICTIM;
        }
        // Check if other init symbols are all finished
        bool run = true;
        for (const auto &initSym: Global::initSecrets) {
            if (secNodeCountPerSymbol.at(initSym) == UINT64_MAX) {
                run = false;
                break;
            }
        }
        if (run) {
            if (!Global::oneOwner) {
                owner = OWNER_ATTACKER;
            }
            for (const auto &sym: *symbols) {
                bool dangling = true;
                for (const auto &initSym: Global::initSecrets) {
                    assert(fromToTotalSCPPCount.at(initSym).at(sym.second) != 0);
                    if (fromToTotalSCPPCount.at(initSym).at(sym.second) != UINT64_MAX) {
                        dangling = false;
                        break;
                    }
                }
                if (dangling) {
                    if (compareAndExchangePropagationStatus(owner, sym.second, Symbol::outputSymbol,
                                                            KnownResults::PropagationStatus::NOT_FOUND,
                                                            KnownResults::PropagationStatus::DISALLOWED)) {
                        stringstream ss;
                        ss << "KnownResults: symbol " << *sym.second << " disallowed in level 1 check for dangling.";
                        log(ss.str());
                        addInvalidSymbol(sym.second);
                    }
                } else {
                    // We only care the from symbol is init symbol and it doesn't matter which specific one.
                    checkLevel2Impossible(*Global::initSecrets.begin(), sym.second);
                }
            }
        }
    } else if (secSymbol != Symbol::outputSymbol) {
        // Disallow from input to med
        if (!Global::oneOwner) {
            owner = OWNER_VICTIM;
        }
        assert(fromToTotalSCPPCount.at(secSymbol).at(Symbol::outputSymbol) != 0);
        if (fromToTotalSCPPCount.at(secSymbol).at(Symbol::outputSymbol) == UINT64_MAX) {
            for (const auto &initSym: Global::initSecrets) {
                compareAndExchangePropagationStatus(owner, initSym, secSymbol,
                                                    KnownResults::PropagationStatus::NOT_FOUND,
                                                    KnownResults::PropagationStatus::DISALLOWED);
            }
            stringstream ss;
            ss << "KnownResults: symbol " << *secSymbol
               << " disallowed in level 1 check for inability to reach output.";
            log(ss.str());
            addInvalidSymbol(secSymbol);
        } else {
            checkLevel2Impossible(secSymbol, Symbol::outputSymbol);
        }
    }
}

void KnownResults::reducePartialPathCount(const shared_ptr<SideChannelPropagation> &prop) {
    assert(fromToTotalSCPPCount.at(prop->from).at(prop->to) != 0 &&
           fromToTotalSCPPCount.at(prop->from).at(prop->to) != UINT64_MAX);
    if (fromToCheckedSCPPCount.at(prop->from).at(prop->to) == UINT64_MAX) {
        fromToCheckedSCPPCount.at(prop->from).at(prop->to) = 0;
    }
    if (++fromToCheckedSCPPCount.at(prop->from).at(prop->to) == fromToTotalSCPPCount.at(prop->from).at(prop->to)) {
        checkLevel2Impossible(prop->from, prop->to);
    }
}

void KnownResults::addInvalidSymbol(const shared_ptr<Symbol> &symbol) {
    _lock.lock();
    invalidSymbols.insert(symbol);
    // -1 to remove output symbol
    validSymbols = symbols->size() - invalidSymbols.size() - 1;
    _lock.unlock();
}

// TOOD: no level 2 discovered?
void KnownResults::checkLevel2Impossible(const shared_ptr<Symbol> &fromSymbol,
                                         const shared_ptr<Symbol> &toSymbol) {
    return;
    // Note it's not possible for both secNodeCountPerSymbol and checkedSecNodeCountPerSymbol being 0 or UINT64_MAX at the same time
    if (secNodeCountPerSymbol.at(fromSymbol) == checkedSecNodeCountPerSymbol.at(toSymbol)) {
        if (!Global::initSecrets.contains(fromSymbol) && fromSymbol != Symbol::outputSymbol &&
            toSymbol == Symbol::outputSymbol) {
            // Disallow init to med
            if (getPropagationStatus(OWNER_ATTACKER, fromSymbol, toSymbol) != PropagationStatus::PROVED) {
                for (const auto &initSymbol: Global::initSecrets) {
                    compareAndExchangePropagationStatus(OWNER_VICTIM, initSymbol, fromSymbol,
                                                        KnownResults::PropagationStatus::NOT_FOUND,
                                                        KnownResults::PropagationStatus::DISALLOWED);
                }
                stringstream ss;
                ss << "KnownResults: symbol " << *fromSymbol
                   << " disallowed in level 2 check for inability to reach output.";
                log(ss.str());
            }
        } else if (Global::initSecrets.contains(fromSymbol) && toSymbol != Symbol::outputSymbol) {
            bool allInitFinishedCheckingToSymbolAndItsNotReachable = true;
            for (const auto &initSyms: Global::initSecrets) {
                if (secNodeCountPerSymbol.at(initSyms) != checkedSecNodeCountPerSymbol.at(initSyms) ||
                    fromToTotalSCPPCount.at(initSyms).at(toSymbol) !=
                    fromToCheckedSCPPCount.at(initSyms).at(toSymbol)) {
                    // sec node not finished or path pair not finished. If init->tosym doesn't exist, we consider it finished checking.
                    allInitFinishedCheckingToSymbolAndItsNotReachable = false;
                } else if (getPropagationStatus(OWNER_VICTIM, initSyms, fromSymbol) == PropagationStatus::PROVED) {
                    allInitFinishedCheckingToSymbolAndItsNotReachable = false;
                }
            }
            if (allInitFinishedCheckingToSymbolAndItsNotReachable) {
                if (compareAndExchangePropagationStatus(OWNER_ATTACKER, toSymbol, Symbol::outputSymbol,
                                                        KnownResults::PropagationStatus::NOT_FOUND,
                                                        KnownResults::PropagationStatus::DISALLOWED)) {
                    stringstream ss;
                    ss << "KnownResults: symbol " << *toSymbol << " disallowed in level 2 check for dangling.";
                    log(ss.str());
                }
            }
        }
    }
}
*/
#endif