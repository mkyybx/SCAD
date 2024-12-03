#include "LogReader.h"

#include <utility>
#include <regex>
#include "Utils.h"
#include "ProgressPrinter.h"
#include <fstream>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/shared_ptr.hpp>
#include <boost/serialization/unordered_map.hpp>
#include <boost/serialization/unordered_set.hpp>

using namespace SCDetector;
using namespace std;

shared_ptr<ParsedLog> LogReader::read() {
    auto ret = make_shared<ParsedLog>();

    if (!cacheDir.empty()) {
        ifstream iCacheStream(cacheDir + "/" + LOG_CACHE_NAME);
        if (iCacheStream.is_open()) {
            boost::archive::binary_iarchive ia(iCacheStream);
            log("LogReader: loading " + cacheDir + "/" + LOG_CACHE_NAME);
            ia >> ret;
            iCacheStream.close();
            log("Before rebuild fkid2fkp, " + to_string(ret->fkgHeads.size()) + " fkg heads");
            // Rebuilt fkid2fkp
            // for (const auto &pOwnerHead: ret->fkgHeads) {
            //     unordered_map<string, uint64_t> stats;
            //     traverseAndShortenPaths(pOwnerHead.second, stats, ret->fkid2fkp[pOwnerHead.first]);
            // }
            Symbol::outputSymbol = ret->symbols[GW_OUTPUT];
            log("After rebuild fkid2fkp, " + to_string(ret->fkgHeads.size()) + " fkg heads");
            return ret;
        }
    }

    // Get # of sub dirs
    atomic<uint64_t> dirCounts = 0;
    while (true) {
        ifstream fileCheck(logDir + "/" + to_string(dirCounts) + "/debug.txt");
        if (fileCheck.is_open()) {
            dirCounts++;
            fileCheck.close();
        } else {
            break;
        }
    }
    log("LogReader: Start reading logs from " + to_string(dirCounts) + " dirs.");

    auto inputQ = make_shared<LogReaderInputQ>();
    auto outputQ = make_shared<LogReaderOutputQ>();
    WorkerPool<shared_ptr<LogReaderWorkerInput>, LogReaderInputTag, shared_ptr<LogReaderWorkerOutput>, LogReaderOutputTag, SIZE_MAX,
            SCD_THREADS * 2, LogReader> wp(&LogReader::worker, inputQ, outputQ, this, "LogReader");
    for (auto i = 0; i < dirCounts; i++) {
        inputQ->putOneClass(make_shared<uint16_t>(i));
    }
    for (auto i = 0; i < SCD_THREADS; i++) {
        auto termsig = termSig;
        // This copy won't affect shared_ptr's comparision. It compares ptr_.get().
        inputQ->putOneClass(std::move(termsig));
    }
    // Merge results
    log("LogReader: Merge results...");
    const auto &progressPrinter = ProgressPrinter::getPrinter();
    unordered_map<uint64_t, unordered_map<uint64_t, shared_ptr<GlobalWrite>>> mergedPathGWS;
    unordered_map<uint8_t, unordered_map<uint64_t, shared_ptr<ForkPoint>>> fkidMap;
    unordered_map<uint8_t, vector<shared_ptr<ForkPoint>>> fkgSubHeads;
    atomic<uint64_t> i = 0;
    progressPrinter->addKey(LOGNAME_LOGREADER, &i, &dirCounts);
    for (; i < dirCounts; i++) {
        auto subRes = outputQ->get();
        ret->paths.insert(subRes->paths.begin(), subRes->paths.end());
        ret->symbols.insert(subRes->symbols.begin(), subRes->symbols.end());
        mergedPathGWS.insert(subRes->pathGWS.begin(), subRes->pathGWS.end());
        for (const auto &pOwnerFkidMap: subRes->fkidMap) {
            auto owner = pOwnerFkidMap.first;
            fkidMap[owner].insert(subRes->fkidMap[owner].begin(), subRes->fkidMap[owner].end());
            fkgSubHeads[owner].insert(fkgSubHeads[owner].end(), subRes->fkgHead[owner].begin(),
                                      subRes->fkgHead[owner].end());
        }
    }
    ret->symbols[GW_OUTPUT] = Symbol::outputSymbol;
    progressPrinter->removeKey(LOGNAME_LOGREADER);
    // Do something related to the path
    log("LogReader: Iterating on path...");
    for (const auto &pPath: ret->paths) {
        auto pathOwner = pPath.second->owner;
        for (const auto &pGW: mergedPathGWS[pPath.first]) {
            // get fkid 2 gws map
            ret->fkid2GWS[pGW.second->fromFkid][pGW.first] = pGW.second;
            // get direct propagation map
            if (pGW.second->summary.varAddrs) {
                for (const auto &var: *(pGW.second->summary.varAddrs)) {
                    const auto &varSymbol = ret->symbols.at(var);
                    const auto &gwSymbol = ret->symbols.at(pGW.first);
                    // This actually won't create empty sets
                    if (!ret->directPropagationMap[pathOwner][varSymbol].contains(gwSymbol)) {
                        ret->directPropagationMap[pathOwner][varSymbol][gwSymbol] = make_shared<unordered_set<shared_ptr<GlobalWrite>>>();
                    }
                    ret->directPropagationMap[pathOwner][varSymbol][gwSymbol]->insert(pGW.second);
                }
            }
            // free the memory
            pGW.second->summary.varAddrs = nullptr;
        }
        // get stats in one loop
        if (pPath.first > ret->maxPathNum) {
            ret->maxPathNum = pPath.first;
        }
    }
    // Assemble the tree
    log("LogReader: Assemble the tree...");
    if (fkgSubHeads.size() != 2) {
        log("fkgSubHeads.size() = " + to_string(fkgSubHeads.size()));
        abort();
    }
    for (const auto &pOwnerSubHeadsArray: fkgSubHeads) {
        auto owner = pOwnerSubHeadsArray.first;
        for (const auto &head: pOwnerSubHeadsArray.second) {
            if (head->fromFkid == FKP_ROOT) {
                ret->fkgHeads[owner] = head;
            } else {
                auto p = fkidMap[owner][head->fromFkid];
                assert(p); // "Dangling fkg head=" << hex << head->fromFkid << ", owner=" << (uint) owner;
                head->parent = p;
                if (head->fromFkid == p->leftFkid) {
                    p->left = head;
                } else if (head->fromFkid == p->rightFkid) {
                    p->right = head;
                } else {
                    log("error: weird tmp and parent pair when merging:" + to_string(head->leftFkid) +
                        to_string(head->rightFkid) + to_string(p->leftFkid) + to_string(p->rightFkid));
                    abort();
                }
            }
        }
    }
    // Diff unfinished vs only available on other owner
    if (ret->fkgHeads.size() == 2) {
        log("LogReader: Fix owner vs unfinished");
        uint64_t counter = 0;
//        setOtherOwnerNodes(ret->fkgHeads.at(OWNER_ATTACKER), ret->fkgHeads.at(OWNER_VICTIM), counter);
        log("LogReader: changed " + to_string(counter) + " unfinished to other owner");
    }
    // Get stats and trim the tree
    log("LogReader: Trim the tree...");
    for (const auto &pOwnerFkgHead: ret->fkgHeads) {
        auto rootNodeType = traverseAndShortenPaths(pOwnerFkgHead.second, ret->fkgStats[pOwnerFkgHead.first],
                                                    ret->fkid2fkp[pOwnerFkgHead.first]);
        // Note this is a lazy way. We can further check the root node using the same logic to trim any other nodes, but it's just unlikely one side root nodes are totally trimmed out.
        assert(rootNodeType == FKP_MIXED);
    }

    // Serialize
    if (!cacheDir.empty()) {
        ofstream oCacheStream(cacheDir + "/" + LOG_CACHE_NAME);
        if (oCacheStream.is_open()) {
            boost::archive::binary_oarchive oa(oCacheStream);
            log("LogReader: saving " + cacheDir + "/" + LOG_CACHE_NAME);
            oa << ret;
            oCacheStream.close();
        } else {
            log("Cache write failed! cacheFile=" + cacheDir + "/" + LOG_CACHE_NAME);
        }
    }

    return ret;
}

LogReader::LogReader(string logDir, string cacheDir) : logDir(std::move(logDir)), cacheDir(std::move(cacheDir)) {}

// Note the input data doesn't contain '\n'
shared_ptr<GlobalWrite>
LogReader::parseGWLine(const string &data, const uint64_t &lineNumber, const uint64_t &processId) {
    static thread_local shared_ptr<GlobalWrite> lastGW = nullptr;
    // regex patterns
    static thread_local auto matchPattern = regex("\\[GW\\],");
    static thread_local auto pathNumPattern = regex("State [0-9]+");
    static thread_local auto timestampPattern = regex("[0-9]+ \\[");
    static thread_local auto varsTrimPattern0 = regex("v[0-9]+_gr");
    static thread_local auto varsTrimPattern1 = regex("_[0-9]+ ");
    static thread_local auto varExtractionPattern = regex("0x[0-9|a-f|A-F]+");
    static thread_local auto exprTrimPattern0 = regex("^\\(assert *");
    static thread_local auto exprTrimPattern1 = regex("\\(= *\\(_ *bv[0-9]+ *[0-9]+\\)");
    static thread_local auto exprTrimPattern2 = regex("\\) *\\)$");

    auto ret = make_shared<GlobalWrite>();

    if (lastGW != nullptr) {
        if (data.starts_with("0x")) {
            ret = lastGW;
            auto iSummary = strtoul(data.c_str(), nullptr, 16);
            ret->summary.expr = "(_ bv" + to_string(iSummary) + ' ' + to_string(ret->size * 8) + ')';
            lastGW = nullptr;
            return ret;
        } else if (data == "(check-sat)") {
            ret = lastGW;
            lastGW = nullptr;
            return ret;
        } else {
            // get additional query string
            if (data.starts_with("(declare-fun")) {
                auto trimmedVar = regex_replace(regex_replace(data, varsTrimPattern0, "gr"), varsTrimPattern1, " ");
                lastGW->summary.vars.insert(trimmedVar);
                // Extract the written var. Used in the later direct propagation graph.
                smatch mres;
                regex_search(trimmedVar, mres, varExtractionPattern);
                if (mres.size() != 1 || !mres[0].str().starts_with("0x")) {
                    log("Regex bug: found weired symbol: " + trimmedVar + ", but expect \"0x[0-9|a-f|A-F]+\"");
                    abort();
                }
                if (!lastGW->summary.varAddrs) {
                    lastGW->summary.varAddrs = make_unique<unordered_set<uint64_t>>();
                }
                lastGW->summary.varAddrs->insert(strtoul(mres[0].str().c_str(), nullptr, 16));
            } else if (data.starts_with("(assert")) {
                if (!lastGW->summary.expr.empty()) {
                    log("BUG: !lastGW->summary.expr.empty()\ndata=" + data + "\nexpr=" + lastGW->summary.expr +
                        "\nln=" + to_string(lineNumber) + "\nprocid=" + to_string(processId));
                }
                lastGW->summary.expr = regex_replace(regex_replace(
                        regex_replace(regex_replace(regex_replace(data, exprTrimPattern0, ""), exprTrimPattern1, ""),
                                      exprTrimPattern2, ""), varsTrimPattern0, "gr"), varsTrimPattern1, " ");
            }
            return nullptr;
        }
    }
    // try finding
    if (!regex_search(data, matchPattern)) {
        return nullptr;
    }
    // split the string
    auto splitedData = Utils::split(data);
    if (splitedData.size() != GW_MEMBER_NUM) {
        log("Regex bug: found " + to_string(splitedData.size()) + " splits in [" + data + "]");
        return nullptr;
    }
    // pasre time
    {
        smatch mres;
        regex_search(splitedData[0], mres, timestampPattern);
        if (mres.empty()) {
            log("Regex bug: found " + splitedData[0] + ", but expect [0-9]+ \\[");
            return nullptr;
        }
        if (Global::maxTimeToRead > 0) {
            auto ts = strtoul(mres[0].str().substr(0, mres[0].length() - 2).c_str(), nullptr, 10);
            // log(to_string(ts));
            if (ts > Global::maxTimeToRead) {
                return nullptr;
            }
        }
    }

    // parse addr
    const auto &addrStr = splitedData[1];
    if (addrStr.size() != 23 && addrStr != "addr=0xdbeef") {
//        log("Regex bug: found " + addrStr + ", but expect 23 chars. Continue check.");
        if (addrStr.substr(0, 7) != "addr=0x") {
            log("Fatal " + addrStr + " returns no GW. " + addrStr.substr(0, 7) + " vs addr=0x");
            return nullptr;
        }
    }
    ret->addr = strtoul(addrStr.substr(5).c_str(), nullptr, 16);

    // parse size
    const auto &sizeStr = splitedData[6];
    if (sizeStr.size() < 6) {
        log("Regex bug: found " + sizeStr + ", but expect >=6 chars.");
        return nullptr;
    }
    ret->size = strtoul(sizeStr.substr(5).c_str(), nullptr, 10);

    // parse out
    const auto &outStr = splitedData[2];
    if (outStr.size() != 5) {
        log("Regex bug: found " + outStr + ", but expect 5 chars.");
        return nullptr;
    }
    ret->out = outStr.substr(4, 5) == "T";
    if (ret->out) {
        ret->addr = GW_OUTPUT;
    }

    // parse path num
    smatch mres;
    regex_search(splitedData[0], mres, pathNumPattern);
    if (mres.empty()) {
        log("Regex bug: found " + splitedData[0] + ", but expect State [0-9]+");
        return nullptr;
    }
    ret->pathNum = strtoul(mres[0].str().substr(6).c_str(), nullptr, 10);

    // parse fkid
    const auto &fkidStr = splitedData[9];
    if (fkidStr.size() < 10) {
        log("Regex bug: found " + fkidStr + ", but expect >= 10 chars");
        return nullptr;
    }
    ret->fromFkid = strtoul(fkidStr.substr(9).c_str(), nullptr, 16);

    // parse pc
    const auto &pcStr = splitedData[7];
    if (pcStr.size() != 21) {
//        log("Regex bug: found " + pcStr + ", but expect 21 chars.");
        if (pcStr.substr(0, 5) != "pc=0x") {
            log("Fatal " + pcStr + " returns no GW. " + addrStr.substr(0, 5) + " vs pc=0x");
            return nullptr;
        }
    }
    ret->pc = strtoul(pcStr.substr(3).c_str(), nullptr, 16);

    // parse summary
    const auto &summaryStr = splitedData[10];
    if (summaryStr.size() < 8) {
        log("Regex bug: found " + summaryStr + ", but expect >= 9 chars");
        return nullptr;
    } else if (summaryStr.size() > 8) {
        auto iSummary = strtoul(summaryStr.substr(8).c_str(), nullptr, 16);
        ret->summary.expr = "(_ bv" + to_string(iSummary) + ' ' + to_string(ret->size * 8) + ')';
    } else {
        // summaryStr.size() == 8
        lastGW = ret;
        return nullptr;
    }

    return ret;
}

shared_ptr<Path> LogReader::parsePCLine(const string &data) {
    static thread_local auto matchPattern = regex("\\[PC\\],");
    static thread_local auto pathNumPattern = regex("State [0-9]+");
    static thread_local auto timestampPattern = regex("[0-9]+ \\[");
    auto ret = make_shared<Path>();
    // try finding
    if (!regex_search(data, matchPattern)) {
        return nullptr;
    }
    // split the string
    auto splitedData = Utils::split(data);
    if (splitedData.size() != PC_MEMBER_NUM) {
        log("Regex bug: found " + to_string(splitedData.size()) + " splits in [" + data + "]");
        return nullptr;
    }
    // pasre time
    {
        smatch mres;
        regex_search(splitedData[0], mres, timestampPattern);
        if (mres.empty()) {
            log("Regex bug: found " + splitedData[0] + ", but expect [0-9]+ \\[");
            return nullptr;
        }
        if (Global::maxTimeToRead > 0) {
            auto ts = strtoul(mres[0].str().substr(0, mres[0].length() - 2).c_str(), nullptr, 10);
            // log(to_string(ts));
            if (ts > Global::maxTimeToRead) {
                return nullptr;
            }
        }
    }
    // parse owner
    const auto &ownerStr = splitedData[1];
    if (ownerStr.size() != 7) {
        log("Regex bug: found " + ownerStr + ", but expect 7 chars.");
        return nullptr;
    }
    ret->owner = strtoul(ownerStr.substr(6).c_str(), nullptr, 10);
    // parse path num
    smatch mres;
    regex_search(splitedData[0], mres, pathNumPattern);
    if (mres.empty()) {
        log("Regex bug: found " + splitedData[0] + ", but expect State [0-9]+");
        return nullptr;
    }
    ret->pathNum = strtoul(mres[0].str().substr(6).c_str(), nullptr, 10);
    return ret;
}

shared_ptr<ForkPoint> LogReader::parseFKGLine(const string &data) {
    static thread_local shared_ptr<ForkPoint> lastFKG = nullptr;
    // regex patterns
    static thread_local auto matchPattern = regex("\\[FKG\\],");
    static thread_local auto timestampPattern = regex("[0-9]+ \\[");
    static thread_local auto pathNumPattern = regex("State [0-9]+");
    static thread_local auto varsTrimPattern0 = regex("v[0-9]+_gr");
    static thread_local auto varsTrimPattern1 = regex("_[0-9]+ ");

    auto ret = make_shared<ForkPoint>();
    if (lastFKG != nullptr) {
        if (data == "(check-sat)") {
            ret = lastFKG;
            lastFKG = nullptr;
            return ret;
        } else {
            // get additional query string
            lastFKG->cond += regex_replace(regex_replace(data, varsTrimPattern0, "gr"), varsTrimPattern1, " ");
            return nullptr;
        }
    }
    // try finding
    if (!regex_search(data, matchPattern)) {
        return nullptr;
    }
    // split the string
    auto splitedData = Utils::split(data);
    if (splitedData.size() != FKG_MEMBER_NUM) {
        log("Regex bug: found " + to_string(splitedData.size()) + " splits in [" + data + "]");
        return nullptr;
    }
    // pasre time
    {
        smatch mres;
        regex_search(splitedData[0], mres, timestampPattern);
        if (mres.empty()) {
            log("Regex bug: found " + splitedData[0] + ", but expect [0-9]+ \\[");
            return nullptr;
        }
        if (Global::maxTimeToRead > 0) {
            auto ts = strtoul(mres[0].str().substr(0, mres[0].length() - 2).c_str(), nullptr, 10);
            // log(to_string(ts));
            if (ts > Global::maxTimeToRead) {
                return nullptr;
            }
        }
    }
    // parse pc
    const auto &addrStr = splitedData[1];
    if (addrStr.size() != 21) {
//        log("Regex bug: found " + addrStr + ", but expect 21 chars. Continue check.");
        if (addrStr.substr(0, 5) != "pc=0x") {
            log("Fatal " + addrStr + " returns no FKG. " + addrStr.substr(0, 5) + " vs pc=0x");
            return nullptr;
        }
    }
    ret->pc = strtoul(addrStr.substr(3).c_str(), nullptr, 16);
    // parse fromFkid
    const auto &fkidStr = splitedData[2];
    if (fkidStr.size() < 7) {
        log("Regex bug: found " + fkidStr + ", but expect >= 7 chars");
        return nullptr;
    }
    ret->fromFkid = strtoul(fkidStr.substr(5).c_str(), nullptr, 16);
    // parse leftFkid
    const auto &leftFkidStr = splitedData[3];
    if (leftFkidStr.size() < 6) {
        log("Regex bug: found " + leftFkidStr + ", but expect >= 6 chars");
        return nullptr;
    }
    ret->leftFkid = strtoul(leftFkidStr.substr(4).c_str(), nullptr, 16);
    // parse rightFkid
    const auto &rightFkidStr = splitedData[4];
    if (rightFkidStr.size() < 6) {
        log("Regex bug: found " + rightFkidStr + ", but expect >= 6 chars");
        return nullptr;
    }
    ret->rightFkid = strtoul(rightFkidStr.substr(4).c_str(), nullptr, 16);
    // parse path num
    smatch mres;
    regex_search(splitedData[0], mres, pathNumPattern);
    if (mres.empty()) {
        log("Regex bug: found " + splitedData[0] + ", but expect State [0-9]+");
        return nullptr;
    }
    ret->pathNum = strtoul(mres[0].str().substr(6).c_str(), nullptr, 10);
    // parse owner
    const auto &ownerStr = splitedData[5];
    if (ownerStr.size() != 7) {
        log("Regex bug: found " + ownerStr + ", but expect 7 chars.");
        return nullptr;
    }
    ret->owner = strtoul(ownerStr.substr(6).c_str(), nullptr, 10);
    if (ret->owner == 0) {
        log("Found FKG Owner = 0" + data + ", treat as unfinished/empty. Only Owner solving TLE can cause this.");
        return nullptr;
    }
    // parse summary
    const auto &summaryStr = splitedData[6];
    if (summaryStr.size() == 6) {
        // the leaf node doesn't have summary.
        return ret;
    } else if (summaryStr.size() == 2) {
        lastFKG = ret;
        return nullptr;
    } else {
        log("Regex bug: found " + summaryStr + ", but expect 2 or 6 chars");
        return nullptr;
    }
}

shared_ptr<Symbol> LogReader::parseSYMLine(const string &data) {
    // regex patterns
    static thread_local auto matchPattern = regex("\\[SYM\\],");
    static thread_local auto pathNumPattern = regex("State [0-9]+");

    // try finding
    if (!regex_search(data, matchPattern)) {
        return nullptr;
    }
    // split the string
    auto splitedData = Utils::split(data);
    if (splitedData.size() != SYM_MEMBER_NUM) {
        log("Regex bug: found " + to_string(splitedData.size()) + " splits in [" + data + "]");
        return nullptr;
    }
    // parse addr
    const auto &addrStr = splitedData[1];
    if (addrStr.size() != 18 && !addrStr.starts_with("0x")) {
        log("Regex bug: found " + addrStr + ", but expect valid addr.");
        return nullptr;
    }
    auto addr = strtoul(addrStr.c_str(), nullptr, 16);
    // parse name
    auto name = splitedData[2];
    // parse size
    const auto &sizeStr = splitedData[3];
    if (sizeStr.size() > 2) {
        log("Regex bug: found " + sizeStr + ", but expect < 2 chars");
        return nullptr;
    }
    auto size = strtoul(sizeStr.c_str(), nullptr, 10);
    // parse initVal
    const auto &initValStr = splitedData[4];
    if (initValStr.size() < 3) {
        log("Regex bug: found " + initValStr + ", but expect >= 3 chars");
        return nullptr;
    }
    auto initVal = strtoul(initValStr.c_str(), nullptr, 16);
    // parse pc
    const auto &pcStr = splitedData[5];
    if (pcStr.size() != 18 && !pcStr.starts_with("0x")) {
        log("Regex bug: found " + pcStr + ", but expect valid addr");
        return nullptr;
    }
    auto pc = strtoul(pcStr.c_str(), nullptr, 16);
    // parse path num
    smatch mres;
    regex_search(splitedData[0], mres, pathNumPattern);
    if (mres.empty()) {
        log("Regex bug: found " + splitedData[0] + ", but expect State [0-9]+");
        return nullptr;
    }
    auto state = strtoul(mres[0].str().substr(6).c_str(), nullptr, 10);

    return make_shared<Symbol>(addr, size, initVal, pc, state, name);
}

void LogReader::worker(const shared_ptr<LogReaderInputQ> &inputQ, const shared_ptr<LogReaderOutputQ> &outputQ) {
    while (true) {
        const auto &input = inputQ->get();
        if (input == termSig) {
            break;
        }
        auto processId = *(input);
        auto ret = make_shared<LogReaderWorkerOutput>();
//        log("Worker, id=" + to_string(processId) + ", this=" + Utils::hexval((uint64_t)this));
        string fileName = logDir + "/" + to_string(processId) + "/debug.txt";
        ifstream ifs(fileName);
        if (!ifs.is_open()) {
            log("LogReader: " + fileName + " open failed, exiting...");
            abort();
        } else {
            string line;
            uint64_t lineNumber = 0;
            while (getline(ifs, line)) {
                lineNumber++;
                // TODO: this can be optimized by explicitly noting the lastGW/C/FKG is not null to save wrong parsing time.
                auto gw = parseGWLine(line, lineNumber, processId);
                if (gw) {
                    assert(!(ret->pathGWS.contains(gw->pathNum) && ret->pathGWS[gw->pathNum].contains(
                            gw->addr)));  // If assert fail -> "BUG: gw.addr in path.gws (two GW with same addr in a path): " + to_string(gw->addr) + " path " + to_string(gw->pathNum));
                    ret->pathGWS[gw->pathNum][gw->addr] = gw;
                    continue;
                }
                auto pc = parsePCLine(line);
                if (pc) {
                    ret->paths[pc->pathNum] = pc;
                    continue;
                }
                auto fkp = parseFKGLine(line);
                if (fkp) {
                    // check if it's common fkp shared by atkr and vctm. TODO: BUG: we can't label when owner=3 and it's unfinished actually.
                    if ((fkp->owner & OWNER_ATTACKER) && (fkp->owner & OWNER_VICTIM)) {
                        auto newFkgPtr = make_shared<ForkPoint>(*fkp);
                        fkp->owner = OWNER_ATTACKER;
                        rflWorkerUpdateFkg(ret->fkidMap[fkp->owner], ret->fkgHead[fkp->owner], fkp);
                        newFkgPtr->owner = OWNER_VICTIM;
                        rflWorkerUpdateFkg(ret->fkidMap[newFkgPtr->owner], ret->fkgHead[newFkgPtr->owner], newFkgPtr);
                    } else {
                        rflWorkerUpdateFkg(ret->fkidMap[fkp->owner], ret->fkgHead[fkp->owner], fkp);
                    }
                    continue;
                }
                auto symbol = parseSYMLine(line);
                if (symbol) {
                    ret->symbols[symbol->addr] = symbol;
                    continue;
                }
            }
            ifs.close();
        }
        outputQ->putOneClass(std::move(ret));
    }
}

// GENERIC_SCOPE, GENERIC_LOGICAL, UNFINISHED, MIXED
uint64_t LogReader::traverseAndShortenPaths(const shared_ptr<ForkPoint> &node, unordered_map<string, uint64_t> &stats,
                                            unordered_map<uint64_t, shared_ptr<ForkPoint>> &fkid2fkp) {
    assert(node);
    fkid2fkp[node->fromFkid] = node;
    stats["Total nodes"] += 1;
    if (Global::fkpTypeName.contains(node->leftFkid)) {
        stats[Global::fkpTypeName.at(node->leftFkid)] += 1;
    } else {
        if (!node->left) {
            stats["Unfinished"] += 1;
        }
        if (!node->right) {
            stats["Unfinished"] += 1;
        }
    }
    /* Trim the tree
     * Unfinished and scope error should be trim-able as we treat those path as illegal and are against any request, see PartialPathGenerator.
     * Logical error should also be trimmed as the global write happening in the middle makes no sense.
     * Terminated nodes shouldn't be trimmed.
     * */
    uint64_t ret;
    if (Utils::isLogicalKilledNode(node->leftFkid)) {
        ret = FKP_KILL_GENERIC_LOGICAL;
    } else if (Utils::isKilledNode(node->leftFkid)) {
        ret = FKP_KILL_GENERIC_SCOPE;
    } else if (node->leftFkid == FKP_TERM) {
        ret = FKP_MIXED;
    } else {
        /* Unfinished or middle nodes
         * 00: both unfinished, return unfinished
         * 01/10: check (maybe 1 is also unfinished) and return
         * 11: check and return
         * */
        auto lret = node->left ? traverseAndShortenPaths(node->left, stats, fkid2fkp) : FKP_UNFINISHED;
        auto rret = node->right ? traverseAndShortenPaths(node->right, stats, fkid2fkp) : FKP_UNFINISHED;
        if (lret == rret) {
            ret = lret;
        } else {
            for (auto i = 0; i < 2; i++) {
                auto &nextNode = i == 0 ? node->left : node->right;
                const auto nextFkid = i == 0 ? node->leftFkid : node->rightFkid;
                const auto subRet = i == 0 ? lret : rret;
                if (subRet != FKP_MIXED) {
                    // Avoid simplifying a single termination node. Unfinished node will always be substituted as there is no termination node for unfinished
                    if (subRet == FKP_UNFINISHED || nextNode->left) {
                        if (nextNode) {
                            // Dangling nodes
                            nextNode->parent = nullptr;
                            nextNode->fromFkid = FKP_KILL_PARENT;
                        }
                        nextNode = ForkPoint::makeNode(nextFkid, node, subRet);
                        fkid2fkp[nextFkid] = nextNode;
                    }
                    stats["After trim, " + Global::fkpTypeName.at(subRet)] += 1;
                }
            }
            ret = FKP_MIXED;
        }
    }
    return ret;
}

void LogReader::rflWorkerUpdateFkg(unordered_map<uint64_t, shared_ptr<ForkPoint>> &subFkidMap,
                                   vector<shared_ptr<ForkPoint>> &subFkgHead, const shared_ptr<ForkPoint> &fkp) {
    if (!subFkidMap.contains(fkp->fromFkid)) {
        subFkgHead.push_back(fkp);
    } else {
        auto p = subFkidMap[fkp->fromFkid];
        fkp->parent = p;
        if (fkp->fromFkid == p->leftFkid) {
            p->left = fkp;
        } else if (fkp->fromFkid == p->rightFkid) {
            p->right = fkp;
        } else {
            log("error: weird tmp and parent pair:" + to_string(fkp->leftFkid) + to_string(fkp->rightFkid) +
                to_string(p->leftFkid) + to_string(p->rightFkid));
            abort();
        }
    }
    // update prevPcMap
    subFkidMap[fkp->leftFkid] = fkp;
    subFkidMap[fkp->rightFkid] = fkp;
}

void LogReader::setOtherOwnerNodes(const shared_ptr<ForkPoint> &lNode, const shared_ptr<ForkPoint> &rNode,
                                   uint64_t &counter) {
    /*
     *       00 01 10 11
     *   00  R Ch Ch  NA
     *   01  Ch Co Ch  NA
     *   10  Ch Ch Co  NA
     *   11  NA NA NA  Co
     * */
    if (lNode->left && !rNode->left) {
        rNode->left = ForkPoint::makeNode(rNode->leftFkid, rNode, FKP_KILL_OTHER_OWNER);
        counter++;
    } else if (!lNode->left && rNode->left) {
        lNode->left = ForkPoint::makeNode(lNode->leftFkid, lNode, FKP_KILL_OTHER_OWNER);
        counter++;
    }
    if (lNode->right && !rNode->right) {
        rNode->right = ForkPoint::makeNode(rNode->rightFkid, rNode, FKP_KILL_OTHER_OWNER);
        counter++;
    } else if (!lNode->right && rNode->right) {
        lNode->right = ForkPoint::makeNode(lNode->rightFkid, lNode, FKP_KILL_OTHER_OWNER);
        counter++;
    }
    if (lNode->left && rNode->left) {
        setOtherOwnerNodes(lNode->left, rNode->left, counter);
    }
    if (lNode->right && rNode->right) {
        setOtherOwnerNodes(lNode->right, rNode->right, counter);
    }
}

namespace SCDetector {
    shared_ptr<LogReaderWorkerInput> LogReader::termSig = make_shared<LogReaderWorkerInput>(UINT16_MAX);
}
