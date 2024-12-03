#include <unistd.h>
#include <thread>
#include <sstream>
#include "ProgressPrinter.h"
#include "GlobalVariables.h"
#include "Utils.h"
#include <atomic>

using namespace std;
using namespace SCDetector;

void ProgressPrinter::addKey(const string &key, atomic<uint64_t> *current, atomic<uint64_t> *total) {
    lock_guard<mutex> lock(m);
    lastMap[key] = 0;
    totalMap[key] = total;
    currentMap[key] = current;
}

ProgressPrinter *SCDetector::ProgressPrinter::getPrinter() {
    lock_guard<mutex> lock(m);
    if (!printer) {
        printer = new ProgressPrinter();
        // Never freed.
    }
    return printer;
}

ProgressPrinter::ProgressPrinter() {
    new thread(&ProgressPrinter::printThread, this);    // Never freed
}

void ProgressPrinter::removeKey(const string &key) {
    lock_guard<mutex> lock(m);
    totalMap.erase(key);
    currentMap.erase(key);
    lastMap.erase(key);
}

void ProgressPrinter::printThread() {
    while (true) {
        m.lock();
        for (const auto &pKeyCurVal: currentMap) {
            const auto &key = pKeyCurVal.first;
            const auto &cur = pKeyCurVal.second;
            const auto &total = totalMap.at(key);

            const auto &last = lastMap.at(key);
            stringstream ss;
            ss << key << ":\t" << *cur << " / " << *total;
            if (*total != 0) {
                ss << " (" << (*cur * 100) / *total << "%)";
            }
            ss << ", speed " << (((float) *cur - (float) last)) / Global::progressPrintInterval << "/s";
            log(ss.str());
            lastMap[key] = *cur;
        }
        m.unlock();
        log("\n");
        sleep(Global::progressPrintInterval);
    }
}

namespace SCDetector {
    ProgressPrinter *ProgressPrinter::printer = nullptr;
    mutex ProgressPrinter::m;
}