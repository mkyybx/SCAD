#include "PartialPathGenerator.h"
#include "Utils.h"

using namespace SCDetector;
using namespace std;

FPPRet PartialPathGenerator::findPartialPath(const shared_ptr<ForkPoint> &node, FPPRes &result, const FPPReq &request,
                                             const shared_ptr<ForkPoint> &topNode, const string &secName) {
    FPPRet ret;
    assert(node);   // Empty node in findPartialPath!
    /* The reason to allow secName-included node to appear under sec node:
     * consider a secnode's left is another secnode and that sub-secnode won't create
     * any compatiable path-pairs. But if we take the main secNode into consideration then we can.
     * If we disallow sub-secnodes, then the main secnode will simply return no left partial pairs and thus causing FNs.
     * The downside is theoratically we can find side channels that don't cover the whole value range of the secret (i.e., >0 and <-100).
     * */
//    if (node->cond.find(secName) != string::npos) {
//        for (const auto &pAddrValPPVec: request) {
//            ret[pAddrValPPVec.first] = false;
//        }
//    } else {
    FPPRet checkResult[2];
    FPPReq newRequest[2];
    for (auto i = 0; i < 2; i++) {
        shared_ptr<ForkPoint> nextNode;
        uint64_t nextFkid;
        if (i == 0) {
            nextNode = node->left;
            nextFkid = node->leftFkid;
        } else {
            nextNode = node->right;
            nextFkid = node->rightFkid;
        }
        if (nextFkid == FKP_TERM || Utils::isLogicalKilledNode(nextFkid)) {
            // Logical kills are due to under-constrained SE. If it's FP it can attribute to SE. Usually such kills are due to illegal state, which can't happen in real.
            for (const auto &pAddrValPPVec: request) {
                checkResult[i][pAddrValPPVec.first] = true;
            }
        } else if (nextFkid == FKP_UNFINISHED || (Utils::isKilledNode(nextFkid))) {
            // Unfinished or scope kills are caused by implementation/scalability problems. FP will arise if we set this to true and we will then overestimate.
            for (const auto &pAddrValPPVec: request) {
                checkResult[i][pAddrValPPVec.first] = false;
            }
        } else {
            // We have a valid next node, build the new request. It can't be ROOT or UNINIT.
            assert(nextFkid != FKP_ROOT && nextFkid != FKP_UNINIT && nextNode);
            for (const auto &pAddrVal: request) {
                const auto &addr = pAddrVal.first;
                if (fkid2GWS->contains(nextFkid) && fkid2GWS->at(nextFkid).contains(addr)) {
                    newRequest[i][addr] = fkid2GWS->at(nextFkid).at(addr);
                } else {
                    newRequest[i][addr] = pAddrVal.second;
                }
            }
            auto subRet = findPartialPath(nextNode, result, newRequest[i], topNode, secName);
            for (const auto &pAddrValPPVec: request) {
                auto addr = pAddrValPPVec.first;
                if (subRet.at(addr)) {
                    if (fkid2GWS->contains(nextFkid) && fkid2GWS->at(nextFkid).contains(addr)) {
                        // Current is not NoWrite
                        const auto &curWrite = fkid2GWS->at(nextFkid).at(addr);
                        if (curWrite->summary != request.at(
                                addr)->summary) {
                            /* This is not accurate but we have further checks in path pair checker.
                             * We don't agree the requested but the sub nodes agree with us. Add partial path.
                             * If it's logical kill then we don't add and return true (special case).
                             **/
                            if (!Utils::isLogicalKilledNode(nextNode->leftFkid)) {
                                result[addr][curWrite->summary.expr].push_back(
                                        make_shared<PartialPath>(curWrite, topNode, nextNode));
                                checkResult[i][addr] = false;
                            } else {
                                checkResult[i][addr] = true;
                            }
                        } else {
                            // We agree with requested
                            checkResult[i][addr] = true;
                        }
                    } else {
                        // We didn't write so we allow what's requested
                        checkResult[i][addr] = true;
                    }
                } else {
                    // If the sub nodes said no, we say no as well
                    checkResult[i][addr] = false;
                }
            }
        }
    }
    // Compare two sides and draw the results
    for (const auto &pAddrValPPVec: request) {
        auto addr = pAddrValPPVec.first;
        // The results should be a and of two sides' sub result.
        ret[addr] = checkResult[0].at(addr) && checkResult[1].at(addr);
        // Add partial paths for cur propagation
        for (auto i = 0; i < 2; i++) {
            auto cur = i;
            auto another = (i == 0 ? 1 : 0);
            const auto &nextNode = i == 0 ? node->left : node->right;
            if (checkResult[cur].at(addr) && !checkResult[another].at(addr) &&
                !Utils::isLogicalKilledNode(nextNode->leftFkid)) {
                // The other side would like to say no, we add our current possible partial path
                // Also skips logical killed nodes
                const auto &gw = newRequest[i][addr];
                result[addr][gw->summary.expr].push_back(make_shared<PartialPath>(gw, topNode, nextNode));
            }
        }
    }
//    }
#ifdef DEBUGTEST
    if (topNode->fromFkid == 0x281f2) {
        log("Node " + Utils::hexval(node->fromFkid) + " returns " +
            (ret.size() == 0 ? "empty ret" : to_string(ret.begin()->second)));
    }
#endif
    return ret;
}

void PartialPathGenerator::partialPathGenerator(const shared_ptr<PPGenInputQ> &inputQ,
                                                const shared_ptr<PPGenOutputQ> &outputQ) {
    while (true) {
        const auto &input = inputQ->get();
        if (input == killSignal) {
            return;
        }
        workingCount++;
        auto buffer = make_shared<vector<shared_ptr<SideChannelPropagation>>>();
        size_t bufferSize = 0; // Since buffer may be moved away, we use a separate var to keep track.
        assert(input->node); // Empty node!
        const auto &fromSymbol = input->secSymbol;

//        if (input->node->fromFkid == 0xf || (!Global::initSecrets.contains(fromSymbol) && fromSymbol->addr != 0xffff88000f152458)) {
//            workingCount--;
//            continue;
//            stringstream ss;
//            ss << "PPGen start working on " << *fromSymbol << ", owner=" << (uint) input->owner << ", fromfkid="
//               << Utils::hexval(input->node->fromFkid);
//            log(ss.str());
//        }

        // Get all possible allowed gw values
        unordered_set<uint64_t> possibleGWWriteAddrs;
        collectPossibleWriteToAddr(input->node, possibleGWWriteAddrs);
#ifdef DEBUGTEST
        if (input->node->fromFkid == 0x281f2 && input->owner == 1 && input->secSymbol->addr == 0xffffffff8305778c) {
            log("Sec node 0x281f2 generate partial paths");
        }
#endif
        // Check the direct propagationsStatus
        if (directPropagationMap->contains(input->owner) &&
            directPropagationMap->at(input->owner).contains(fromSymbol)) {
            const auto &directPropagations = directPropagationMap->at(input->owner).at(fromSymbol);
            for (const auto &pToSymGWs: directPropagations) {
                if (knownResults->isPropagationAllowed(input->owner, fromSymbol, pToSymGWs.first)) {
                    // Build model query
                    const auto &selectedGW = *pToSymGWs.second->begin();
                    const auto &btmNode = fkid2fkp->at(input->owner).at(selectedGW->fromFkid);
                    auto &&prop = make_shared<SideChannelPropagation>(input->commonPartialPath,
                                                                      make_shared<DirectPropagation>(pToSymGWs.second,
                                                                                                     input->node,
                                                                                                     btmNode,
                                                                                                     selectedGW),
                                                                      fromSymbol, pToSymGWs.first, input->owner);
                    if (!runSolver ||
                        (pathPairChecker && pathPairChecker->checkingWorkerImpl(prop))) {
                        // Sync mode, including lazy mode (no solver run)
                        knownResults->setPropagationStatus(prop->owner, prop->from,
                                                           prop->to,
                                                           KnownResults::PropagationStatus::PROVED);
                        ppCheckOutputQ->putOneClass(std::move(prop));
                    } else if (!pathPairChecker) {
#ifdef DEBUGTEST
                        if (input->node->fromFkid == 0x281f2 && input->owner == 1 &&
                            input->secSymbol->addr == 0xffffffff8305778c) {
                            log("Sec node 0x281f2 generate found direct propagation");
                        }
#endif
                        // Async mode
                        if (bufferSize >= bufferMaxSize) {
                            outputQ->putOneClass(std::move(buffer));
                            buffer = make_shared<vector<shared_ptr<SideChannelPropagation>>>();
                            bufferSize = 0;
                        }
                        buffer->push_back(std::move(prop));
                        bufferSize++;
                    }
                }
                // Remove it from addrs to check. If it's allowed, we remove. If it's not allowed, it won't be allowed in indirect propagation either.
                possibleGWWriteAddrs.erase(pToSymGWs.first->addr);
            }
        }
        // Trim the possible write addrs
        unordered_set<uint64_t> newPossibleGWWriteAddrs;
        for (const auto &addr: possibleGWWriteAddrs) {
            if (knownResults->isPropagationAllowed(input->owner, fromSymbol, symbols->at(addr))) {
                newPossibleGWWriteAddrs.insert(addr);
            }
        }
        possibleGWWriteAddrs = newPossibleGWWriteAddrs;
        // get left and right side results
        FPPRes result[2];
        for (auto i = 0; i < 2; i++) {
            shared_ptr<ForkPoint> nextNode = nullptr;
            uint64_t nextFkid;
            FPPRet subret;
            if (i == 0) {
                nextNode = input->node->left;
                nextFkid = input->node->leftFkid;
            } else {
                nextNode = input->node->right;
                nextFkid = input->node->rightFkid;
            }
            assert(!Utils::isSpecialNode(nextFkid) &&
                   nextNode);    // termination node shouldn't include the secret in condition!
            // init the request
            FPPReq request;
            for (auto addr: possibleGWWriteAddrs) {
                auto gw = GlobalWrite::gwNoWrite;
                if (fkid2GWS->contains(nextFkid) &&
                    fkid2GWS->at(nextFkid).contains(addr)) {
                    gw = fkid2GWS->at(nextFkid).at(addr);
                }
                request[addr] = gw;
            }
            subret = findPartialPath(nextNode, result[i], request, input->node, fromSymbol->addrStr);
            // analyze the return as the top node
            for (auto addr: possibleGWWriteAddrs) {
                if (subret[addr] && !Utils::isLogicalKilledNode(nextNode->leftFkid)) {
                    // Sub nodes allow us to use the value in the init request, add to partial path
                    const auto &gw = request.at(addr);
                    result[i][addr][gw->summary.expr].push_back(
                            make_shared<PartialPath>(gw, input->node, nextNode));
                }
            }
        }
#ifdef DEBUGTEST
        /* This is for mid->out
         * */
        if (input->node->fromFkid == 0x281f2 && input->owner == 1 && input->secSymbol->addr == 0xffffffff8305778c) {
            log("Sec node 0x281f2 left partial path size=" + to_string(result[0].size()) + ", right size=" +
                to_string(result[1].size()));
        }
        /* This is for input->mid
         * */
        uint64_t mid = 0xffffffff83057790;
        if (input->node->fromFkid == 0x1a && input->owner == 2) {
            int64_t leftSize = result[0].contains(mid) ? int64_t(result[0].at(mid).size()) : -1;
            int64_t rightSize = result[1].contains(mid) ? int64_t(result[1].at(mid).size()) : -1;
            log("Sec node 0x1a left partial path size for " + to_string(mid) + " = " + to_string(leftSize) +
                ", right size = " + (to_string(rightSize)));
            if (leftSize < 10) {
                for (const auto& pSummaryArray : result[0].at(mid)) {
                    log("Left: " + pSummaryArray.first + ", size = " + to_string(pSummaryArray.second.size()));
                    for (const auto& pp: pSummaryArray.second) {
                        if (!pp->gw.empty() && pp->gw.begin()->second->fromFkid == 0xb566f) {
                            log("Left found 0xb566f");
                        }
                    }
                }
            }
            if (rightSize < 10) {
                for (const auto& pSummaryArray : result[1].at(mid)) {
                    log("Right: " + pSummaryArray.first + ", size = " + to_string(pSummaryArray.second.size()));
                    for (const auto& pp: pSummaryArray.second) {
                        if (!pp->gw.empty() && pp->gw.begin()->second->fromFkid == 0xb566f) {
                            log("Right found 0xb566f");
                        }
                    }
                }
            }
        }
#endif
        // Build the path pairs to check
        if (!result[0].empty() && !result[1].empty()) {


            // tests
//            for (auto i = 0; i < 2; i++) {
//                for (const auto &pAddrValPPVec: result[i]) {
//                    auto addr = pAddrValPPVec.first;
//                    if (addr != 0xffffffff8212331c) {
//                        continue;
//                    }
//                    uint64_t exprCount = 0;
//                    uint64_t nwPPCount = 0;
//                    uint64_t normalPPCount = 0;
//                    for (const auto &pExprPPVec: pAddrValPPVec.second) {
//                        exprCount++;
//                        if (pExprPPVec.first == GW_NW) {
//                            nwPPCount += pExprPPVec.second.size();
//                        } else {
//                            normalPPCount += pExprPPVec.second.size();
//                        }
//                    }
//                    log(Utils::hexval(input->node->fromFkid) + "'s result " + to_string(i) + ": exprCount=" +
//                        to_string(exprCount) + ", nwPPCount=" + to_string(nwPPCount) + ", normalPPCount=" +
//                        to_string(normalPPCount));
//                }
//            }

            // Build all possible path pairs
            // Just to get the addr, 0 or 1 doesn't matter. They should have the same addr set.
            for (const auto &pAddrValPPVec: result[0]) {
                auto addr = pAddrValPPVec.first;
                if (knownResults->isPropagationAllowed(input->owner, fromSymbol, symbols->at(addr))) {
                    const auto &toSymbol = symbols->at(addr);
                    // One side write (cur side no write)
                    for (auto i = 0; i < 2; i++) {
                        auto curSide = i;
                        auto anotherSide = (i == 0 ? 1 : 0);
                        if (result[curSide].at(addr).contains(GW_NW)) {
                            const auto &ppVec = result[curSide].at(addr).at(GW_NW);
                            for (const auto &pAnotherValPPVec: result[anotherSide].at(addr)) {
                                const auto &val = pAnotherValPPVec.first;
                                if (val != GW_NW && val != GW_NA) {
                                    for (const auto &pp0: ppVec) {
                                        for (const auto &pp1: pAnotherValPPVec.second) {
                                            auto &&prop = make_shared<SideChannelPropagation>(i == 0 ? pp0 : pp1,
                                                                                              i == 0 ? pp1 : pp0,
                                                                                              input->commonPartialPath,
                                                                                              fromSymbol, toSymbol,
                                                                                              input->owner);
//#ifdef NO_MED_TO_MED
//                                            knownResults->addPartialPathCount(fromSymbol, toSymbol);
//#endif

                                            if (!runSolver ||
                                                (pathPairChecker && pathPairChecker->checkingWorkerImpl(prop))) {
                                                // Sync mode, including lazy mode (no solver run)
                                                knownResults->setPropagationStatus(prop->owner, prop->from,
                                                                                   prop->to,
                                                                                   KnownResults::PropagationStatus::PROVED);
                                                ppCheckOutputQ->putOneClass(std::move(prop));
                                                if (!runSolver) {
                                                    goto out;
                                                }
                                            } else if (!pathPairChecker) {
                                                // Async mode
                                                if (bufferSize >= bufferMaxSize) {
                                                    outputQ->putOneClass(std::move(buffer));
                                                    buffer = make_shared<vector<shared_ptr<SideChannelPropagation>>>();
                                                    bufferSize = 0;
                                                }
                                                buffer->push_back(std::move(prop));
                                                bufferSize++;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Two sides writes
                    for (const auto &lPValPPVec: result[0].at(addr)) {
                        auto lVal = lPValPPVec.first;
                        if (lVal != GW_NW && lVal != GW_NA) {
                            for (const auto &lpp: lPValPPVec.second) {
                                for (const auto &rPValPPVec: result[1].at(addr)) {
                                    auto rVal = rPValPPVec.first;
                                    if (rVal != GW_NW && rVal != GW_NA) {
                                        for (const auto &rpp: rPValPPVec.second) {
                                            auto &&prop = make_shared<SideChannelPropagation>(lpp, rpp,
                                                                                              input->commonPartialPath,
                                                                                              fromSymbol, toSymbol,
                                                                                              input->owner);
//#ifdef NO_MED_TO_MED
//                                            knownResults->addPartialPathCount(fromSymbol, toSymbol);
//#endif
                                            if (!runSolver ||
                                                (pathPairChecker && pathPairChecker->checkingWorkerImpl(prop))) {
                                                /* Sync mode, including lazy mode (no solver run)
                                                 * In lazy mode, we can compare the two GWs, if they are same then we don't output. Just a basic heuristic.
                                                 * */
                                                if (runSolver || prop->pp.at(0)->gw.begin()->second->summary !=
                                                                 prop->pp.at(1)->gw.begin()->second->summary) {
                                                    knownResults->setPropagationStatus(prop->owner, prop->from,
                                                                                       prop->to,
                                                                                       KnownResults::PropagationStatus::PROVED);
                                                    ppCheckOutputQ->putOneClass(std::move(prop));
                                                }
                                                if (!runSolver) {
                                                    goto out;
                                                }
                                            } else if (!pathPairChecker) {
                                                // Async mode
                                                if (bufferSize >= bufferMaxSize) {
                                                    outputQ->putOneClass(std::move(buffer));
                                                    buffer = make_shared<vector<shared_ptr<SideChannelPropagation>>>();
                                                    bufferSize = 0;
                                                }
                                                buffer->push_back(std::move(prop));
                                                bufferSize++;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    out:
                    0;
                }
            }
        }
//#ifdef NO_MED_TO_MED
//        knownResults->reduceSecNodesCount(fromSymbol);
//#endif
        if (bufferSize > 0) {
            outputQ->putOneClass(std::move(buffer));
        }

//        if (input->node->fromFkid == 0xf) {
//            stringstream ss1;
//            ss1 << "PPGen finished working on " << *fromSymbol << ", owner=" << (uint) input->owner << ", fromfkid="
//                << Utils::hexval(input->node->fromFkid);
//            log(ss1.str());
//        }

        workingCount--;
    }
}

void
PartialPathGenerator::collectPossibleWriteToAddr(const shared_ptr<ForkPoint> &node, unordered_set<uint64_t> &result) {
    if (node) {
        if (fkid2GWS->contains(node->leftFkid)) {
            for (const auto &p: fkid2GWS->at(node->leftFkid)) {
                if (!result.contains(p.first)) {
                    result.insert(p.first);
                }
            }
        }
        if (fkid2GWS->contains(node->rightFkid)) {
            for (const auto &p: fkid2GWS->at(node->rightFkid)) {
                if (!result.contains(p.first)) {
                    result.insert(p.first);
                }
            }
        }
        collectPossibleWriteToAddr(node->left, result);
        collectPossibleWriteToAddr(node->right, result);
    }
}

PartialPathGenerator::PartialPathGenerator(const shared_ptr<Symbols> &symbols, const shared_ptr<Fkid2GWS> &fkid2Gws,
                                           const shared_ptr<unordered_map<uint8_t, DirectPropagationMap>> &directPropagationMap,
                                           const shared_ptr<KnownResults> &knownResults,
                                           const shared_ptr<Fkid2Fkp> &fkid2Fkp, const shared_ptr<PPGenInputQ> &inputQ,
                                           const shared_ptr<PPGenOutputQ> &outputQ,
                                           const shared_ptr<PPCheckOutputQ> &ppCheckOutputQ,
                                           const shared_ptr<PathPairChecker> &pathPairChecker, bool runSolver) : Worker(
        runSolver ? "PartialPathGeneratorWithSolver" : "PartialPathGenerator"), symbols(symbols), fkid2GWS(fkid2Gws),
                                                                                                                 directPropagationMap(
                                                                                                                         directPropagationMap),
                                                                                                                 knownResults(
                                                                                                                         knownResults),
                                                                                                                 fkid2fkp(
                                                                                                                         fkid2Fkp),
                                                                                                                 PPGwp(&PartialPathGenerator::partialPathGenerator,
                                                                                                                       inputQ,
                                                                                                                       outputQ,
                                                                                                                       this,
                                                                                                                       "PartialPathGenerator"),
                                                                                                                 ppCheckOutputQ(
                                                                                                                         ppCheckOutputQ),
                                                                                                                 pathPairChecker(
                                                                                                                         pathPairChecker),
                                                                                                                 runSolver(
                                                                                                                         runSolver) {}

void PartialPathGenerator::setBufferMaxSize(uint64_t _bufferMaxSize) {
    PartialPathGenerator::bufferMaxSize = _bufferMaxSize;
}


PPGenInput::PPGenInput(const shared_ptr<ForkPoint> &node, const shared_ptr<Symbol> &secSymbol, uint8_t owner,
                       const shared_ptr<PartialPath> &commonPartialPath) : node(node), secSymbol(secSymbol),
                                                                           owner(owner),
                                                                           commonPartialPath(commonPartialPath) {}

namespace SCDetector {
    uint64_t PartialPathGenerator::bufferMaxSize;
    const shared_ptr<PPGenInput> PartialPathGenerator::killSignal = nullptr;
}