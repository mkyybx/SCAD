#ifndef SCDETECTOR2_PROGRESSPRINTER_H
#define SCDETECTOR2_PROGRESSPRINTER_H

#include <cstdint>
#include <string>
#include <unordered_map>
#include <map>
#include <mutex>

using namespace std;
namespace SCDetector {
    class ProgressPrinter {
    private:
        map<string, atomic<uint64_t>*> currentMap;
        unordered_map<string, atomic<uint64_t>*> totalMap;
        unordered_map<string, uint64_t> lastMap;
        static mutex m;
        static ProgressPrinter *printer;

        ProgressPrinter();

        void printThread();

    public:
        void addKey(const string &key, atomic<uint64_t>* current, atomic<uint64_t>* total);

        void removeKey(const string &key);

        static ProgressPrinter *getPrinter();
    };
}


#endif //SCDETECTOR2_PROGRESSPRINTER_H
