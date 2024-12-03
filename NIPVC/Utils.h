#ifndef SCDETECTOR2_UTILS_H
#define SCDETECTOR2_UTILS_H

#include <string>
#include <vector>
#include "Using.h"

#define log(expr) SCDetector::Utils::output(expr)

using namespace std;

namespace SCDetector {
    class Utils {

    public:
        static string hexval(uint64_t val);

        static void output(const string &s);

        static vector<string> split(const string &str);

        static bool isKilledNode(uint64_t fkid);

        static bool isLogicalKilledNode(uint64_t fkid);

        static bool isSpecialNode(uint64_t fkid);

        static uint randomSelect(const vector<uint64_t> &probArray);

        static string myExec(const string &cmd);

        static string runAddr2Line(uint64_t addr, const string &imagePath);

        static unordered_map<uint64_t, uint64_t> checkFate(const shared_ptr<ForkPoint> &node);

        // From bottom to sec node to top
        static string getExecutionTrace(const shared_ptr<ForkPoint> &bottomNode, const shared_ptr<ForkPoint> &secNode,
                                        const string &binaryImageFile);

        static string getModel(const shared_ptr<ForkPoint> &bottomNode);
    };
}


#endif //SCDETECTOR2_UTILS_H
