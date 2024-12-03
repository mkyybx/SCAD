#include "SecNodeFinder.h"
#include "BasicType.h"
#include "PartialPathGenerator.h"
#include "Utils.h"

using namespace SCDetector;
using namespace std;

void SecNodeFinder::secNodeFinder(const shared_ptr<SNFInputQ> &inputQ, const shared_ptr<SNFOutputQ> &outputQ) {
    while (true) {
        const auto &input = inputQ->get();
        if (input == killSignal) {
            return;
        }
        workingCount++;
        const auto &sym = get<0>(*input);
        auto owner = get<1>(*input);
#ifdef NO_MED_TO_MED
        if (Global::oneOwner || !(Global::initSecrets.contains(sym) ^ (owner == OWNER_VICTIM))) {
#endif
            uint64_t secNodeCount = 0;
            if (sym != Symbol::outputSymbol) {
                if (findSecNode(fkgHead->at(owner), sym, outputQ, owner, secNodeCount)) {
                    // Not found any node
                    assert(secNodeCount == 0);
                    knownResults->addDisallowedTo(sym, owner);
                    knownResults->addDisallowedFrom(sym, owner);
//#ifdef NO_MED_TO_MED
//                knownResults->addInvalidSymbol(sym);
//#endif
                }
            }
            secNameChecked.at(owner)++;
            stringstream ss;
            ss << "SecNodeFinder: Finished finding " << secNodeCount << " nodes for " << *sym << " for owner "
               << (uint) owner;
            log(ss.str());
#ifdef NO_MED_TO_MED
        }
#endif
        workingCount--;
    }
}

bool SecNodeFinder::findSecNode(const shared_ptr<ForkPoint> &node, const shared_ptr<Symbol> &secSym,
                                const shared_ptr<SNFOutputQ> &outputQ, const uint8_t &owner, uint64_t &secNodeCount) {
    auto ret = true;
    if (node) {
#ifdef DEBUGTEST
        if (node->fromFkid == 0x281f2 && owner == 1 && secSym->addr == 0xffffffff8305778c) {
            log("Sec node 0x281f2 cond=" + node->cond + ", secname=" + secSym->addrStr);
        }
#endif
        if (node->cond.find(secSym->addrStr) != string::npos) {
            shared_ptr<PartialPath> parentPath;
            // Build parent partial path
            parentPartialPathMapLock.lock();
            if (!parentPartialPathMap.contains(node)) {
                parentPath = make_shared<PartialPath>(fkgHead->at(owner), node);
                parentPartialPathMap[node] = parentPath;
            } else {
                parentPath = parentPartialPathMap.at(node);
            }
            parentPartialPathMapLock.unlock();
//#ifdef NO_MED_TO_MED
//            knownResults->addSecNodesCount(secSym);
//#endif
            assert(parentPath);
            outputQ->put(make_tuple(secSym, owner), make_shared<PPGenInput>(node, secSym, owner, parentPath));
#ifdef DEBUGTEST
            if (node->fromFkid == 0x281f2 && owner == 1 && secSym->addr == 0xffffffff8305778c) {
                log("Sec node 0x281f2 found");
            }
#endif
            secNodeCount++;
            ret = false;
        }
        ret &= findSecNode(node->left, secSym, outputQ, owner, secNodeCount);
        ret &= findSecNode(node->right, secSym, outputQ, owner, secNodeCount);
    }
    return ret;
}

SecNodeFinder::SecNodeFinder(const shared_ptr<KnownResults> &knownResults, const shared_ptr<FkgHeads> &fkgHead,
                             const shared_ptr<SNFInputQ> &inputQ, const shared_ptr<SNFOutputQ> &outputQ)
        : Worker("SecNodeFinder"), knownResults(knownResults), fkgHead(fkgHead),
          wp(&SecNodeFinder::secNodeFinder, inputQ, outputQ, this, "SecNodeFinder") {
    // Init secNameChecked
    for (const auto &pOwnerHead: *fkgHead) {
        secNameChecked[pOwnerHead.first] = 0;
        ProgressPrinter::getPrinter()->addKey(LOGNAME_SNFINDER_SNCHECKED + to_string(pOwnerHead.first),
                                              &secNameChecked[pOwnerHead.first], &Global::totalSymbols);
    }
}

SecNodeFinder::~SecNodeFinder() {
    for (const auto &pOwnerCounter: secNameChecked) {
        ProgressPrinter::getPrinter()->removeKey(LOGNAME_SNFINDER_SNCHECKED + to_string(pOwnerCounter.first));
    }
}

namespace SCDetector {
    const shared_ptr<SNFInput> SecNodeFinder::killSignal = nullptr;
}