#include "Z3Manager.h"
#include "Dijkstra.h"
#include "ResultPrinter.h"
#include <sstream>
#include <chrono>
#include <iostream>
#include <cassert>
#include <random>
#include "Utils.h"
#include "GlobalVariables.h"

using namespace std;
using namespace SCDetector;

string Utils::hexval(uint64_t val) {
    stringstream ss;
    ss << hex << "0x" << val;
    return ss.str();
}

void Utils::output(const string &s) {
    static auto startTime = chrono::system_clock::now();
    static mutex lock;
    auto t = chrono::system_clock::to_time_t(chrono::system_clock::now()) - chrono::system_clock::to_time_t(startTime);
    lock.lock();
    cout << '[' << t << "s]\t" << s << endl;
    lock.unlock();
}

vector<string> Utils::split(const string &str) {
    stringstream ss(str);
    string segment;
    vector<std::string> seglist;

    while (std::getline(ss, segment, ',')) {
        seglist.push_back(segment);
    }

    return seglist;
}

bool Utils::isKilledNode(uint64_t fkid) {
    // This can return true. False alarm. Not sure why.
    if (fkid > FKP_KILL_START && fkid < FKP_KILL_END) {
        return true;
    } else {
        return false;
    }
}

uint Utils::randomSelect(const vector<uint64_t> &probArray) {
    uint64_t total = 0;
    for (const auto &val: probArray) {
        total += val;
    }
    assert(total > 0);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(0, total - 1);

    uint64_t sel = dis(gen);
    uint64_t cum = 0;
    for (size_t i = 0; i < probArray.size(); ++i) {
        cum += probArray[i];
        if (cum > sel) {
            return i;
        }
    }
    assert(false);  // This is impossible.
}


bool Utils::isSpecialNode(uint64_t fkid) {
    return Global::fkpTypeName.contains(fkid);
}

string Utils::myExec(const string &cmd) {
    const int max_buffer_size = 4096;
    char *buffer = new char[max_buffer_size];
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        log("popen() failed for " + cmd);
        return "";
    }
    while (fgets(buffer, max_buffer_size, pipe.get()) != nullptr) {
        result += buffer;
    }
    delete[] buffer;
    return result;
}

string Utils::runAddr2Line(uint64_t addr, const string &imagePath) {
    if (Global::imageAddrOffset != 0) {
        addr -= Global::imageAddrOffset;
    }
    if (imagePath.empty()) {
        return hexval(addr);
    }
    stringstream inputss;
//    inputss << "addr2line -e " << imagePath << " -ipfCsa " << hex << addr;
    inputss << "llvm-symbolizer-14 -e " << imagePath << " -ipfCsa " << hexval(addr);
//    log("Execute " + inputss.str());
    return myExec(inputss.str());
}

bool Utils::isLogicalKilledNode(uint64_t fkid) {
    return fkid == FKP_KILL_GENERIC_LOGICAL || fkid == FKP_KILL_NA || fkid == FKP_KILL_PANIC ||

           fkid == FKP_KILL_INFEASIBLE_PATH || fkid == FKP_KILL_OTHER_OWNER;
}

unordered_map<uint64_t, uint64_t> Utils::checkFate(const shared_ptr<ForkPoint> &node) {
    unordered_map<uint64_t, uint64_t> ret;
    queue<shared_ptr<ForkPoint>> q;
    q.push(node);
    while (!q.empty()) {
        auto n = q.front();
        q.pop();
        if (isSpecialNode(n->leftFkid)) {
            ret[n->leftFkid] += 1;
        } else {
            if (n->left) {
                q.push(n->left);
            }
            if (n->right) {
                q.push(n->right);
            }
        }
    }
    return ret;
}

string Utils::getExecutionTrace(const shared_ptr<ForkPoint> &bottomNode, const shared_ptr<ForkPoint> &secNode,
                                const string &binaryImageFile) {
    vector<tuple<uint64_t, bool, uint64_t>> pcs;
    auto node = bottomNode;
    while (node && node->parent) {
        if (node == node->parent->left) {
            pcs.emplace_back(node->pc, false, node->fromFkid);
        } else {
            assert(node == node->parent->right);
            pcs.emplace_back(node->pc, true, node->fromFkid);
        }
        node = node->parent;
    }
    stringstream ss;
    for (int64_t i = pcs.size() - 1; i >= 0; i--) {
        ss << hex << (get<2>(pcs[i]) == secNode->fromFkid ? "*(" : "(") << (!get<1>(pcs[i]) ? "\u2199" : "\u2198")
           << get<2>(pcs[i]) << ")\t" << runAddr2Line(get<0>(pcs[i]), binaryImageFile);
        if (binaryImageFile.empty()) {
            // Windows only. 0xFFFFF801AB750000 is the tcpip.sys base of the sepcific snapshot
            ss << "\t(" << hexval(get<0>(pcs[i]) - 0xFFFFF801AB750000) << ")\n";
        }
    }
    return ss.str();
}

string Utils::getModel(const shared_ptr<ForkPoint> &bottomNode) {
    auto node = bottomNode;
    while (node && node->parent) {
        node = node->parent;
    }
    PartialPath pp(node, bottomNode);
    auto bundle = Global::solverManager->getSolverBundle();
    pp.addToSolver(bundle, "");
    auto checkResult = Global::solverManager->checkSolver(bundle);
    if (checkResult != SolverCheckResult::SAT) {
        return "UNSAT or TIMEOUT: " + to_string((int)checkResult);
    }
    return Global::solverManager->dumpModel(bundle);
}
