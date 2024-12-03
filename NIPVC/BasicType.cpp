#include <sstream>
#include <utility>
#include <cassert>
#include "BasicType.h"
#include "Utils.h"
#include <regex>
#include "ProgressPrinter.h"

using namespace SCDetector;
using namespace std;

shared_ptr<ForkPoint> ForkPoint::makeNode(uint64_t fromFkid, const shared_ptr<ForkPoint> &parent, uint64_t nextFkid) {
    auto ret = make_shared<ForkPoint>();
    ret->parent = parent;
    ret->fromFkid = fromFkid;
    ret->leftFkid = nextFkid;
    ret->rightFkid = nextFkid;
    ret->owner = parent->owner;
    // Path num has no use of now, so we ignore as of now
    // pc also has no meaning in such a node
    return ret;
}

bool ParsedGW::operator<(const ParsedGW &other) const {
    return expr < other.expr;
}

bool ParsedGW::operator==(const ParsedGW &other) const {
    return expr == other.expr;
}

bool ParsedGW::operator!=(const ParsedGW &other) const {
    return expr != other.expr;
}

bool ParsedGW::operator>(const ParsedGW &other) const {
    return expr > other.expr;
}

void Symbol::init() {
    // Size set to 1 to avoid generating invalid smt strings
    outputSymbol = make_shared<Symbol>(GW_OUTPUT, 1, 0, GW_OUTPUT, 0, "GW_OUTPUT");
}

Symbol::Symbol(uint64_t addr, uint8_t size, uint64_t initVal, uint64_t pc, uint64_t state, string name) : addr(addr),
                                                                                                          size(size),
                                                                                                          initVal(initVal),
                                                                                                          pc(pc),
                                                                                                          state(state),
                                                                                                          name(std::move(
                                                                                                                  name)),
                                                                                                          addrStr(Utils::hexval(
                                                                                                                  addr)) {
    buildDefaultGW();
}

void Symbol::buildDefaultGW() {
    assert(!defaultGW);
    defaultGW = make_shared<GlobalWrite>();
    defaultGW->size = size;
    defaultGW->addr = addr;
    defaultGW->pathNum = state;
    defaultGW->pc = pc;
    defaultGW->summary.expr = "(_ bv" + to_string(initVal) + ' ' + to_string(size * 8) + ')';
}

SideChannelPropagation::SideChannelPropagation(const shared_ptr<PartialPath> &pp0, const shared_ptr<PartialPath> &pp1,
                                               const shared_ptr<PartialPath> &commonPartialPath,
                                               const shared_ptr<Symbol> &from, const shared_ptr<Symbol> &to,
                                               uint8_t owner) : from(from), to(to), owner(owner),
                                                                commonPartialPath(commonPartialPath) {
    pp[0] = pp0;
    pp[1] = pp1;
    // Build type
    if (pp[0]->gw.begin()->second == GlobalWrite::gwNoWrite || pp[1]->gw.begin()->second == GlobalWrite::gwNoWrite) {
        if (Global::initSecrets.contains(from)) {
            propagationType = PropagationType::CK_SEC_ONE;
        } else if (to == Symbol::outputSymbol) {
            propagationType = PropagationType::CK_OUT_ONE;
        } else {
            propagationType = PropagationType::CK_MED_ONE;
        }
    } else {
        if (Global::initSecrets.contains(from)) {
            propagationType = PropagationType::CK_SEC_TWO;
        } else if (to == Symbol::outputSymbol) {
            propagationType = PropagationType::CK_OUT_TWO;
        } else {
            propagationType = PropagationType::CK_MED_TWO;
        }
    }
}

shared_ptr<DijkstraPropagationMap> SideChannelPropagation::toDijkstraMap(const PropagationMap &input) {
    auto ret = make_shared<DijkstraPropagationMap>();
    for (const auto &pFromToMap: input) {
        for (const auto &pToData: pFromToMap.second) {
            const auto &propagations = pToData.second;
            if (!propagations.propagations.empty()) {
                (*ret)[pFromToMap.first][pToData.first] = 2;
//                    for (const auto &scpp: *scppVec) {
//                        if (scpp.directPropagation) {
//                            (*ret)[pFromToMap.first][pToData.first] = 1;
//                            break;
//                        }
//                    }
            }
        }
    }
    return ret;
}

SolverCheckResult SideChannelPropagation::buildModel(shared_ptr<SolverBundle> &bundle) {
    SolverCheckResult ret;
    if (directPropagation) {
        PartialPath(directPropagation->gwUsedForModelQuery, fkgHeads->at(owner),
                    directPropagation->bottomNode).addToSolver(bundle, "");
        ret = Global::solverManager->checkSolver(bundle);
    } else {
        ret = checkSat(bundle);
    }
    assert(ret != SolverCheckResult::UNSAT);
    return ret;
}

void PartialPath::addToSolver(const shared_ptr<SolverBundle> &bundle, const string &secNameToReplace) const {
    auto node = bottom;
    if (secNameToReplace.empty()) {
        while (node != top) {
            if (node == node->parent->left) {
                Global::solverManager->addSMT(bundle, node->parent->cond, false);
            } else {
                Global::solverManager->addSMT(bundle, node->parent->cond, true);
            }
            node = node->parent;
        }
    } else {
        regex re(secNameToReplace);
        while (node != top) {
            if (node == node->parent->left) {
                Global::solverManager->addSMT(bundle, regex_replace(node->parent->cond, re,
                                                                    secNameToReplace + SHADOW_VAR_SUFFIX), false);
            } else {
                Global::solverManager->addSMT(bundle, regex_replace(node->parent->cond, re,
                                                                    secNameToReplace + SHADOW_VAR_SUFFIX), true);
            }
            node = node->parent;
        }
    }
}

PartialPath::PartialPath(const shared_ptr<ForkPoint> &top, const shared_ptr<ForkPoint> &bottom) : top(top),
                                                                                                  bottom(bottom) {
    assert(bottom != nullptr && top != nullptr && ((bottom->parent != nullptr && !bottom->parent->cond.empty()) ||
                                                   (bottom == top && top->fromFkid == FKP_ROOT)) && fkid2GWS);
    // Build gw set if it's set for parent partial paths
    auto node = bottom;
    while (node != top) {
        if (fkid2GWS->contains(node->fromFkid)) {
            for (const auto &pGW: fkid2GWS->at(node->fromFkid)) {
                if (!this->gw.contains(pGW.first)) {
                    this->gw[pGW.first] = pGW.second;
                }
            }
        }
        node = node->parent;
    }
}

void PartialPath::setFkid2Gws(
        const shared_ptr<unordered_map<uint64_t, unordered_map<uint64_t, shared_ptr<GlobalWrite>>>> &fkid2Gws) {
    fkid2GWS = fkid2Gws;
}

PartialPath::PartialPath(const shared_ptr<GlobalWrite> &gw, const shared_ptr<ForkPoint> &top,
                         const shared_ptr<ForkPoint> &bottom) : top(top), bottom(bottom) {
    assert(bottom != nullptr && top != nullptr && bottom->parent != nullptr &&
           !bottom->parent->cond.empty() && bottom != top);
//    if (bottom->fromFkid == 1685190) {
//        log("debugging");
//    }
    this->gw[gw->addr] = gw;
}

void GlobalWrite::init() {
    gwNA = make_shared<GlobalWrite>();
    gwNA->summary.expr = GW_NA;
    gwNA->pc = 0x1;
    gwNA->addr = 0x1;
    gwNoWrite = make_shared<GlobalWrite>();
    gwNoWrite->summary.expr = GW_NW;
    gwNoWrite->pc = 0x2;
    gwNoWrite->addr = 0x2;
}

void GlobalWrite::addDiffGWQueryToSolver(const shared_ptr<SolverBundle> &bundle, const shared_ptr<GlobalWrite> &gw0,
                                         const shared_ptr<GlobalWrite> &gw1) {
    if (!gw0 ^ !gw1) {
        // Either one is null, they are different
        Global::solverManager->addTrueExpr(bundle);
    } else if (!gw0 && !gw1) {
        // Both are null, same
        Global::solverManager->addFalseExpr(bundle);
    } else {
        // Both aren't null
        assert(gw0->addr == gw1->addr);
        if (gw0->summary == gw1->summary) {
            Global::solverManager->addFalseExpr(bundle);
        } else {
            auto s = string("(set-logic QF_AUFBV )\n");
            auto varSet = gw0->summary.vars;
            varSet.insert(gw1->summary.vars.begin(), gw1->summary.vars.end());
            for (const auto &var: varSet) {
                s += var + '\n';
            }
            if (gw0->size == gw1->size) {
                s += "(assert (=  " + gw0->summary.expr + ' ' + gw1->summary.expr + ") )";
            } else if (gw0->size > gw1->size) {
                s += "(assert (= ( (_ extract " + to_string(gw1->size * 8 - 1) + "  0) " + gw0->summary.expr + ") " +
                     gw1->summary.expr + ") )";
            } else {
                // gw0->size < gw1->size
                s += "(assert (=  " + gw0->summary.expr + " ( (_ extract " + to_string(gw0->size * 8 - 1) + " 0) " +
                     gw1->summary.expr + ") ) )";
            }
            try {
                Global::solverManager->addSMT(bundle, s, true);
            } catch (const exception &ex) {
                stringstream ss;
                ss << ex.what() << ", gw0 fkid=" << hex << gw0->fromFkid << ", addr=" << gw0->addr << ", gw1 fkid="
                   << gw1->fromFkid << ", addr=" << gw1->addr;
                log(ss.str());
                abort();
            }
        }
    }
}

DirectPropagation::DirectPropagation(const shared_ptr<unordered_set<shared_ptr<GlobalWrite>>> &gws,
                                     const shared_ptr<ForkPoint> &secNode, const shared_ptr<ForkPoint> &bottomNode,
                                     const shared_ptr<GlobalWrite> &gwUsedForModelQuery) : gws(gws), secNode(secNode),
                                                                                           bottomNode(bottomNode),
                                                                                           gwUsedForModelQuery(
                                                                                                   gwUsedForModelQuery) {}


void SideChannelPropagation::setFkgHeads(const shared_ptr<FkgHeads> &f) {
    SideChannelPropagation::fkgHeads = f;
}

SolverCheckResult SideChannelPropagation::checkSat(shared_ptr<SolverBundle> &bundle) {
    assert(!directPropagation);
    auto addr = to->addr;
#ifdef DEBUGTEST
    bool sat[3] = {false, false, false};
#endif
    // Add parents
    commonPartialPath->addToSolver(bundle, "");
    commonPartialPath->addToSolver(bundle, from->addrStr);
#ifdef DEBUGTEST
//    if (Global::solverManager->checkSolver(bundle) == SolverCheckResult::SAT) {
//        sat[0] = true;
//    }
#endif
    // Add partial paths
    pp[0]->addToSolver(bundle, "");
    pp[1]->addToSolver(bundle, from->addrStr);
#ifdef DEBUGTEST
//    if (Global::solverManager->checkSolver(bundle) == SolverCheckResult::SAT) {
//        sat[1] = true;
//    }
#endif
    // Add GW diff query
    shared_ptr<GlobalWrite> gw[2] = {nullptr, nullptr};
    for (auto i = 0; i < 2; i++) {
        if (pp[i]->gw.begin()->second != GlobalWrite::gwNoWrite) {
            // It's written
            gw[i] = pp[i]->gw.begin()->second;
        } else if (commonPartialPath->gw.contains(addr)) {
            // Written in parent edges
            gw[i] = commonPartialPath->gw.at(addr);
        } else {
            // Not written at all
//            gw[i] = to->defaultGW;
        }
    }
    GlobalWrite::addDiffGWQueryToSolver(bundle, gw[0], gw[1]);
#ifdef DEBUGTEST
//    if (Global::solverManager->checkSolver(bundle) == SolverCheckResult::SAT) {
//        sat[2] = true;
//    }
    /* This is for mid -> out
     * */
    /*
    if (pp[0]->top->fromFkid == 0x281f2 && owner == 1 && from->addr == 0xffffffff8305778c) {
        stringstream ss;
        ss << "pp[0]=" << Utils::hexval(pp[0]->bottom->fromFkid) << ", pp[1]=" << Utils::hexval(pp[1]->bottom->fromFkid)
           << ", sat=" << sat[0] << "," << sat[1] << "," << sat[2] << ", query="
           << Global::solverManager->dumpSMT2(bundle);
        log(ss.str());
    }
     */
    /* This is for input->mid
     * */
    shared_ptr<GlobalWrite> interestedGW = nullptr;
    for (int i = 0; i <= 1; i++) {
        if (pp[i]->gw.begin()->second != GlobalWrite::gwNoWrite) {
            interestedGW = pp[i]->gw.begin()->second;
        }
    }
    if (interestedGW && interestedGW->fromFkid == 0xb566f && interestedGW->addr == 0xffffffff83057790) {
        stringstream ss;
        ss << "pp[0]=" << Utils::hexval(pp[0]->bottom->fromFkid) << ", pp[1]=" << Utils::hexval(pp[1]->bottom->fromFkid)
           << ", sat=" << sat[0] << "," << sat[1] << "," << sat[2] << ", query="
           << Global::solverManager->dumpSMT2(bundle);
        log(ss.str());
    }
#endif
    return Global::solverManager->checkSolver(bundle);
}

SideChannelPropagation::SideChannelPropagation(const shared_ptr<PartialPath> &commonPartialPath,
                                               const shared_ptr<DirectPropagation> &directPropagation,
                                               const shared_ptr<Symbol> &from, const shared_ptr<Symbol> &to,
                                               uint8_t owner) : commonPartialPath(commonPartialPath),
                                                                directPropagation(directPropagation), from(from),
                                                                to(to), owner(owner) {
    // Build type
    if (Global::initSecrets.contains(from)) {
        propagationType = PropagationType::CK_SEC_DIRECT;
    } else if (to == Symbol::outputSymbol) {
        propagationType = PropagationType::CK_OUT_DIRECT;
    } else {
        propagationType = PropagationType::CK_MED_DIRECT;
    }
}

void SideChannelPropagation::init() {
    auto temp = new(SideChannelPropagation);
    dummyProp.reset(temp);
//    ProgressPrinter::getPrinter()->addKey("SideChannelPropagation -- parent failed count", &parentFailedCount, &parentFailedCount);
//    ProgressPrinter::getPrinter()->addKey("SideChannelPropagation -- child failed count", &childFailedCount, &childFailedCount);
//    ProgressPrinter::getPrinter()->addKey("SideChannelPropagation -- gw failed count", &gwFailedCount, &gwFailedCount);
}

namespace SCDetector {
    shared_ptr<GlobalWrite> GlobalWrite::gwNA;
    shared_ptr<GlobalWrite> GlobalWrite::gwNoWrite;
    shared_ptr<Symbol> Symbol::outputSymbol;
    shared_ptr<unordered_map<uint64_t, unordered_map<uint64_t, shared_ptr<GlobalWrite>>>> PartialPath::fkid2GWS;
    shared_ptr<FkgHeads> SideChannelPropagation::fkgHeads;
    shared_ptr<SideChannelPropagation> SideChannelPropagation::dummyProp;
}

namespace std {
    ostream &operator<<(ostream &os, const GlobalWrite &gw) {
        os << "[GW],addr=" << Utils::hexval(gw.addr) << ",size=" << (uint) gw.size << ",out=" << gw.out << ",pn="
           << gw.pathNum << ",fromfkid=" << Utils::hexval(gw.fromFkid) << ",pc="
           << Utils::runAddr2Line(gw.pc, Global::binaryImagePath) << ",gw=\n" << gw.summary;
        return os;
    }

    ostream &operator<<(ostream &os, const ParsedGW &summary) {
        for (const auto &v: summary.vars) {
            os << v << "\n";
        }
        os << summary.expr << "\n";
        return os;
    }

    ostream &operator<<(ostream &os, const SCDetector::Symbol &symbol) {
        if (!symbol.name.empty()) {
            os << symbol.name;
        } else {
            os << symbol.addrStr;
        }
        os << "(" << (uint) symbol.size << "),pc=" << Utils::hexval(symbol.pc);
        return os;
    }
}