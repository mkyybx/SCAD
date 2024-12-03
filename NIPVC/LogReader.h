#ifndef SCDETECTOR2_LOGREADER_H
#define SCDETECTOR2_LOGREADER_H

#include <string>
#include <boost/serialization/access.hpp>
#include <unordered_map>
#include "BasicType.h"
#include "WorkerPool.h"
#include <vector>
#include "Using.h"

using namespace std;
namespace SCDetector {
    class ParsedLog {
    private:
        friend class boost::serialization::access;

        template<class Archive>
        void serialize(Archive &ar, const unsigned int) {
            ar & paths;
            ar & fkgHeads;
            ar & fkid2GWS;
            ar & maxPathNum;
            ar & fkgStats;
            ar & symbols;
            ar & directPropagationMap;
            ar & fkid2fkp; // (Perhaps due to stack overflow. Let's give it another try). We didn't serialize fkid2fkp as it's buggy. We'll rebuild it each time.
        }

    public:
        Paths paths;
        FkgHeads fkgHeads; // owner -> head
        Fkid2GWS fkid2GWS;
        uint64_t maxPathNum = 0;
        FkgStats fkgStats; // owner->stats
        Fkid2Fkp fkid2fkp; // owner -> fkid -> fkp
        Symbols symbols;
        unordered_map<uint8_t, DirectPropagationMap> directPropagationMap; // owner -> from -> tolist
    };

    class LogReaderWorkerOutput {
    public:
        unordered_map<uint64_t, shared_ptr<Path>> paths;
        unordered_map<uint8_t, unordered_map<uint64_t, shared_ptr<ForkPoint>>> fkidMap; // owner->fromFkid->FKP
        unordered_map<uint8_t, vector<shared_ptr<ForkPoint>>> fkgHead; // owner->[fk heads, ...]
        Symbols symbols;
        unordered_map<uint64_t, unordered_map<uint64_t, shared_ptr<GlobalWrite>>> pathGWS;
    };

    class LogReader {
    private:
        string logDir;
        string cacheDir;

        static shared_ptr<GlobalWrite>
        parseGWLine(const string &data, const uint64_t &lineNumber, const uint64_t &processId);

        static shared_ptr<Path> parsePCLine(const string &data);

        static shared_ptr<ForkPoint> parseFKGLine(const string &data);

        static shared_ptr<Symbol> parseSYMLine(const string &data);

        uint64_t traverseAndShortenPaths(const shared_ptr<ForkPoint> &node, unordered_map<string, uint64_t> &stats,
                                         unordered_map<uint64_t, shared_ptr<ForkPoint>> &fkid2fkp);

        void setOtherOwnerNodes(const shared_ptr<ForkPoint>& lHead, const shared_ptr<ForkPoint>& rHead, uint64_t& counter);

        static void rflWorkerUpdateFkg(unordered_map<uint64_t, shared_ptr<ForkPoint>> &subFkidMap,
                                       vector<shared_ptr<ForkPoint>> &subFkgHead, const shared_ptr<ForkPoint> &fkp);

        void worker(const shared_ptr<LogReaderInputQ> &inputQ, const shared_ptr<LogReaderOutputQ> &outputQ);

        static shared_ptr<LogReaderWorkerInput> termSig;

    public:
        LogReader(string logDir, string cacheDir);

        shared_ptr<ParsedLog> read();
    };
}

#endif //SCDETECTOR2_LOGREADER_H
