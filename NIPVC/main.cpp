#include <sstream>
#include "Z3Manager.h"
#include "BasicType.h"
#include "Utils.h"
#include "LogReader.h"
#include "SCDLooper.h"

using namespace std;
using namespace SCDetector;

void staticInit(uint64_t LRUSize, uint64_t solverTaskBatchSize) {
    Global::solverManager = make_shared<Z3Manager>(LRUSize);
    Symbol::init();
    Global::init();
    GlobalWrite::init();
    SideChannelPropagation::init();
    PartialPathGenerator::setBufferMaxSize(solverTaskBatchSize);
}

// TODO: check if fkid2gws is correct
int main(int argc, char **argv) {
    srand(time(nullptr));
    // Temp vars
    unordered_set<string> initSecNames;
    string logDir;
    string cacheDir;
    string outputDir;
    string binaryImage;
    uint64_t looperTimeout;
    uint64_t lruCacheSize;
    uint64_t solverTaskBatchSize;
    uint64_t ckProb[(size_t) PropagationType::CK_NUM_TYPES];
    uint64_t testFromFkid = 0;
    uint64_t imageAddrOffset = 0;
    uint64_t maxTimeToRead = 0;
    // Loop on the options
    int opt;
    unordered_set<int> parsedArgs;
    const string shortopts = "l:t:p:i:s:c:o:d:b:r:g:T:O:S:";
    while ((opt = getopt(argc, argv, shortopts.c_str())) != -1) {
        parsedArgs.insert(opt);
        switch (opt) {
            case 'l':
                Global::progressPrintInterval = strtoul(optarg, nullptr, 10);
                if (Global::progressPrintInterval == 0) {
                    log("Fatal: log print interval cannot be 0.");
                    abort();
                }
                log("Log interval = " + to_string(Global::progressPrintInterval));
                break;
            case 't':
                Global::solverTimeout = strtoul(optarg, nullptr, 10);
                log("Solver timeout = " + to_string(Global::solverTimeout));
                break;
            case 'p': {
                auto strRatioVec = Utils::split(optarg);
                if (strRatioVec.size() == (size_t) PropagationType::CK_NUM_TYPES) {
                    uint64_t total = 0;
                    for (auto i = 0; i < (size_t) PropagationType::CK_NUM_TYPES; i++) {
                        ckProb[i] = strtoul(strRatioVec[i].c_str(), nullptr, 10);
#ifdef NO_MED_TO_MED
                        if ((i == (unsigned long) PropagationType::CK_MED_ONE ||
                             i == (unsigned long) PropagationType::CK_MED_TWO) && ckProb[i] != 0) {
                            log("Fatal: non-zero med-to-med propagation ratio in no-med-to-med mode.");
                            abort();
                        }
#endif
                        total += ckProb[i];
                    }
                    if (total >= RAND_MAX) {
                        log("Fatal: sum of ckprob too big!");
                        abort();
                    }
                } else {
                    log("Expect exact " + to_string((size_t) PropagationType::CK_NUM_TYPES) + " ratios!");
                    abort();
                }
                stringstream ss;
                ss << "Probability ratios = ";
                for (const auto &i: ckProb) {
                    ss << i << " ";
                }
                log(ss.str());
            }
                break;
            case 'i': {
                auto initSecs = Utils::split(optarg);
                for (const auto &secName: initSecs) {
                    initSecNames.insert(secName);
                }
                stringstream ss;
                ss << "Init secs = ";
                for (const auto &secName: initSecNames) {
                    ss << secName << " ";
                }
                log(ss.str());
            }
                break;
            case 's': {
                logDir = optarg;
                log("Log dir = " + logDir);
                break;
            }
            case 'c': {
                cacheDir = optarg;
                log("Cache dir = " + cacheDir);
                break;
            }
            case 'o': {
                outputDir = optarg;
                log("Output dir = " + outputDir);
                break;
            }
            case 'd': {
                looperTimeout = strtoul(optarg, nullptr, 10);
                log("Looper timeout = " + to_string(looperTimeout));
                break;
            }
            case 'b': {
                binaryImage = optarg;
                log("Binary image = " + binaryImage);
                break;
            }
            case 'r': {
                lruCacheSize = strtoul(optarg, nullptr, 10);
                log("LRU cache size = " + to_string(lruCacheSize));
                break;
            }
            case 'g': {
                solverTaskBatchSize = strtoul(optarg, nullptr, 10);
                log("Solver Task Batch Size = " + to_string(solverTaskBatchSize));
                break;
            }
            case 'T' : {
                testFromFkid = strtoul(optarg, nullptr, 10);
                log("Test from fkid = " + to_string(testFromFkid));
                break;
            }
            case 'O' : {
                imageAddrOffset = strtoul(optarg, nullptr, 16);
                log("imageAddrOffset = " + to_string(imageAddrOffset));
                break;
            }
            case 'S' : {
                maxTimeToRead = strtoul(optarg, nullptr, 10);
                log("maxTimeToRead = " + to_string(maxTimeToRead));
                break;
            }
            default:
                log("Usage: " + string(argv[0]) + " [-l Log interval in s] [-t Solver timeout in ms] [-p " +
                    to_string((size_t) PropagationType::CK_NUM_TYPES) +
                    " comma-separated probability ratios for checking path pairs] [-i Init secrets separated by comma] [-s Log input dir] [-c Cache dir] [-o Output dir] [-d Duration to run the analysis in s] [-b Binary image for addr2line] [-r LRU cache size]");
                return 1;
        }
    }
    // Check missing arguments
//    if (parsedArgs.size() != shortopts.size() / 2) {
//        log("Missing options. All options are required.");
//        abort();
//    }
    // Do static init
    staticInit(lruCacheSize, solverTaskBatchSize);
    Global::binaryImagePath = binaryImage;
    Global::imageAddrOffset = imageAddrOffset;
    Global::maxTimeToRead = maxTimeToRead;
    // Launch log reader
    auto logReader = LogReader(logDir, cacheDir);
    auto parsedLog = logReader.read();  // This should not be freed
    // Print stats
    stringstream ss;
    ss << parsedLog->symbols.size() << " symbols, " << parsedLog->fkgHeads.size() << " owners, "
       << parsedLog->paths.size() << " paths, max path num=" << parsedLog->maxPathNum << "\n";
    for (const auto &pOwnerKV: parsedLog->fkgStats) {
        ss << "\n";
        ss << "Owner " << (uint) pOwnerKV.first << ":\n";
        for (const auto &pKV: pOwnerKV.second) {
            ss << pKV.first << ":\t" << pKV.second << "\n";
        }
    }
    log(ss.str());
    // Test
    if (testFromFkid != 0) {
        for (const auto &pOwnerHead: parsedLog->fkgHeads) {
            stringstream ss;
            ss << "Fate of node " << Utils::hexval(testFromFkid) << " on owner " << (uint) pOwnerHead.first;
            if (parsedLog->fkid2fkp.at(pOwnerHead.first).contains(testFromFkid)) {
                const auto& node = parsedLog->fkid2fkp.at(pOwnerHead.first).at(testFromFkid);
                if (node->left) {
                    ss << ", L:\n";
                    const auto &ret = Utils::checkFate(node->left);
                    for (const auto &pRetCount: ret) {
                        ss << Utils::hexval(pRetCount.first) << ": " << pRetCount.second << "\n";
                    }
                }
                if (node->right) {
                    ss << ", R:\n";
                    const auto &ret = Utils::checkFate(node->right);
                    for (const auto &pRetCount: ret) {
                        ss << Utils::hexval(pRetCount.first) << ": " << pRetCount.second << "\n";
                    }
                }
            } else {
                ss << " doesn't exist.\n";
            }
            if (parsedLog->fkid2fkp.at(pOwnerHead.first).contains(testFromFkid)) {
                const auto &node = parsedLog->fkid2fkp.at(pOwnerHead.first).at(testFromFkid);
                ss << "Trace on owner " << (uint) pOwnerHead.first << ":\n"
                   << Utils::getExecutionTrace(node, node, binaryImage);
                // buggy
//                ss << "\n model: " << Utils::getModel(node);
            }
            log(ss.str());
        }
        exit(0);
    }
    // Another test
//    {
//        uint64_t secNodeId = 0x4b1;
//        uint8_t owner = 1;
//        uint64_t leftBottomId =
//        // Build common partial path
//        auto parentPath = make_shared<PartialPath>(fkgHead->at(owner), node);
//    }

    Global::totalSymbols = parsedLog->symbols.size();
    // Do some init for the main loop
    auto noop_deleter = [](auto *ptr) { log("noop_deleter called on " + Utils::hexval((unsigned long) ptr)); };
    shared_ptr<Fkid2GWS> fkid2GWS(&parsedLog->fkid2GWS, noop_deleter);
    shared_ptr<Symbols> symbols(&parsedLog->symbols, noop_deleter);
    shared_ptr<Fkid2Fkp> fkid2fkp(&parsedLog->fkid2fkp, noop_deleter);
    shared_ptr<unordered_map<uint8_t, DirectPropagationMap>> directPropagationMap(&parsedLog->directPropagationMap,
                                                                                  noop_deleter);
    shared_ptr<FkgHeads> fkgHeads(&parsedLog->fkgHeads, noop_deleter);
    PartialPath::setFkid2Gws(fkid2GWS);
    SideChannelPropagation::setFkgHeads(fkgHeads);
    for (const auto &secName: initSecNames) {
        Global::initSecrets.insert(parsedLog->symbols.at(strtoul(secName.c_str(), nullptr, 16)));
    }
    // TODO: Think about how to build "chances" if NO_MED_TO_MED is not defined
#ifdef NO_MED_TO_MED
    unordered_map<PPGenInputTag, uint64_t, boost::hash<PPGenInputTag>> ppGenInputChances;
    unordered_map<PPCheckInputTag, uint64_t, boost::hash<PPCheckInputTag>> ppCheckInputChances; // Currently no use
    // Init : others = 1:1
    for (const auto &pAddrSym: *symbols) {
        const auto &sym = pAddrSym.second;
        for (const auto &pOwnerHead: *fkgHeads) {
            if (Global::initSecrets.contains(sym)) {
                ppGenInputChances[make_tuple(sym, pOwnerHead.first)] = symbols->size() - Global::initSecrets.size();
            } else {
                ppGenInputChances[make_tuple(sym, pOwnerHead.first)] = Global::initSecrets.size();
            }
        }
    }
    // Use the prob provided by the user
//    for (const auto &pOwnerHeads: *fkgHeads) {
//        for (const auto &pStrSym0: *symbols) {
//            for (const auto &pStrSym1: *symbols) {
//                for (auto i = 0; i < (size_t) PropagationType::CK_NUM_TYPES; i++) {
//                    ppCheckInputChances[make_tuple(pStrSym0.second, pStrSym1.second, pOwnerHeads.first,
//                                                   (PropagationType) i)] = ckProb[i];
//                }
//            }
//        }
//    }
#endif

    // Launch the main loop
    SCDLooperRet scdRet;
    {
        SCDLooper phase1Looper(looperTimeout, outputDir, binaryImage, fkid2GWS, symbols, fkid2fkp, directPropagationMap,
                               fkgHeads,
                               ppGenInputChances, ppCheckInputChances, nullptr);
        scdRet = phase1Looper.join();
        log("Phase 1 finished.");
    }
    if (get<0>(scdRet) >= looperTimeout && looperTimeout > 0) {
        log("No time for Phase 2, exit.");
    } else {
        // Get num of shared vars
        uint64_t sharedVarCount = 0;
        for (const auto &pInitSymSharedVarSet: *get<1>(*get<1>(scdRet))) {
            sharedVarCount += pInitSymSharedVarSet.second.size();
        }
        log(to_string(looperTimeout - get<0>(scdRet)) + "s remaining, " + to_string(sharedVarCount) + " shared vars.");
        SCDLooper phase2Looper(looperTimeout == 0 ? 0 : looperTimeout - get<0>(scdRet), outputDir, binaryImage,
                               fkid2GWS, symbols, fkid2fkp, directPropagationMap, fkgHeads, ppGenInputChances,
                               ppCheckInputChances, get<1>(scdRet));

        get<1>(scdRet) = nullptr;
        phase2Looper.join();
    }
    exit(0);
}