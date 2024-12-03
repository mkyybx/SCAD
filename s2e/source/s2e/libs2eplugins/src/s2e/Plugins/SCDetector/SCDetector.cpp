#include <klee/util/ExprSMTLIBPrinter.h>
#include <unordered_map>
#include "SCDetector.h"
#include "Kernel310TCPModel.h"
#include "Kernel44UDPModel.h"
#include "X86_64LinuxKernelModel.h"
#include "Kernel48TCPModel.h"
#include "Kernel6132TCPModel.h"
#include "Kernel6132TCPModelWithOption.h"
#include "Kernel6132UDPModel.h"
#include "NTKernelModel.h"
#include "WindowsServerTCPModel.h"
#include "FreeBSDKernelModel.h"
#include "FreeBSDTCPModel.h"
#include "X86_64LinuxUserSpaceModel.h"
#include "LWIPTCPModel.h"

using namespace s2e;
using namespace s2e::plugins;

S2E_DEFINE_PLUGIN(Propagator, "Propagate the secret to global var", "Propagator", "BaseInstructions",
                  "MyExecutionMonitor", "MyTracer");

void Propagator::initialize() {
    ConfigFile *config = s2e()->getConfig();
    m_base = s2e()->getPlugin<BaseInstructions>();
    m_monitor = s2e()->getPlugin<MyExecutionMonitor>();
    m_tracer = s2e()->getPlugin<MyTracer>();
    lastForkTime = 0;
    lastForkTimeState = -1;
    auto cfgKey = getConfigKey();
    bool ok;


    // Get secret addresses
    std::vector<std::string> secretSections = config->getListKeys(cfgKey + ".secrets");
    for (auto &secretSection: secretSections) {
        uint64_t addr = config->getInt(cfgKey + ".secrets." + secretSection + ".addr", 0, &ok);
        std::string description = config->getString(cfgKey + ".secrets." + secretSection + ".description",
                                                    std::to_string(addr),
                                                    &ok);
        uint8_t len = config->getInt(cfgKey + ".secrets." + secretSection + ".length", 0, &ok);
        if (!ok || addr == 0 || len == 0) {
            g_s2e->getWarningsStream() << "Cannot find secrets addr for '"
                                       << cfgKey + ".secrets." + secretSection + ".addr"
                                       << "'\n";
            exit(-1);
        }
        // record
        secrets[secretSection] = Secret(addr, len, description, secretSection);
    }
    getDebugStream() << "Got secret addresses" << "\n";

/*
    // Get entry functions
    std::vector<std::string> entryFuncSections = config->getListKeys(cfgKey + ".entryfunc");
    for (auto &entryFuncSection: entryFuncSections) {
        uint64_t addr = config->getInt(cfgKey + ".entryfunc." + entryFuncSection + ".addr", 0, &ok);
        std::string description = config->getString(cfgKey + ".entryfunc." + entryFuncSection + ".description",
                                                    std::to_string(addr),
                                                    &ok);
        if (addr == 0) {
            g_s2e->getWarningsStream() << "Cannot find entryFunc addr for '"
                                       << cfgKey + ".entryfunc." + entryFuncSection + ".addr"
                                       << "'\n";
            exit(-1);
        }
        // hook
        m_monitor->hookAddress(addr, sigc::mem_fun(*this, &Propagator::onEntryFunction));
    }
    getDebugStream() << "Get entry functions" << "\n";

    // Get global variables
    std::vector<std::string> globalVarSections = config->getListKeys(cfgKey + ".globalVars");
    for (auto &globalVarSection: globalVarSections) {
        uint64_t addr = config->getInt(cfgKey + ".globalVars." + globalVarSection + ".addr", 0, &ok);
        uint8_t len = config->getInt(cfgKey + ".globalVars." + globalVarSection + ".length", 0, &ok);
        if (!ok || addr == 0 || len == 0) {
            g_s2e->getWarningsStream() << "Cannot find global var addr for '"
                                       << cfgKey + ".globalVars." + globalVarSection + ".addr"
                                       << "'\n";
            exit(-1);
        }
        // record
        globalVars[addr] = GlobalVar(addr, len, globalVarSection, globalVarSection);
    }
    getDebugStream() << "Get global variables" << "\n";

    // Get output points
//    std::vector<std::string> outputSections = config->getListKeys(cfgKey + ".outputs");
//    for (auto &outputSection: outputSections) {
//        uint64_t funcEntryAddr = config->getInt(cfgKey + ".outputs." + outputSection + ".funcEntryAddr", 0, &ok);
//        uint8_t regOffset = config->getInt(cfgKey + ".outputs." + outputSection + ".regOffset", 0, &ok);
//        uint8_t regLen = config->getInt(cfgKey + ".outputs." + outputSection + ".regLen", 0, &ok);
//        uint64_t structOffset = config->getInt(cfgKey + ".outputs." + outputSection + ".structMemOffset", 0, &ok);
//        uint8_t structMemberLen = config->getInt(cfgKey + ".outputs." + outputSection + ".structMemberLen", 0, &ok);
//        if (!ok || funcEntryAddr == 0 || regLen == 0 || structMemberLen == 0) {
//            g_s2e->getWarningsStream() << "Cannot find output for '"
//                                       << cfgKey + ".outputs." + outputSection + ".funcEntryAddr"
//                                       << "'\n";
//            exit(-1);
//        }
//        // record
//        // currently we do not support monitoring two args in a single function
//        outputPoints[funcEntryAddr] = OutputPoint(outputSection, funcEntryAddr, regOffset, regLen, structOffset,
//                                                  structMemberLen);
//        // hook to record info
//        getDebugStream() << "mky: hooking " << hexval(funcEntryAddr) << "\n";
//        m_monitor->hookAddress(funcEntryAddr, sigc::mem_fun(*this, &Propagator::onOutputFunction));
//    }
//    getDebugStream() << "Get output points" << "\n";
     */

    // Get disallowedGWRanges, where the global variable may cause trouble and thus we don't want to fork on that global variable
    std::vector<std::string> noForkLocationsSections = config->getListKeys(cfgKey + ".disallowedGWRanges");
    for (auto &noForkLocation: noForkLocationsSections) {
        uint64_t startAddr = config->getInt(cfgKey + ".disallowedGWRanges." + noForkLocation + ".startAddr", 0, &ok);
        uint64_t endAddr = config->getInt(cfgKey + ".disallowedGWRanges." + noForkLocation + ".endAddr", 0, &ok);
        if (!ok || startAddr == 0 || endAddr == 0) {
            g_s2e->getWarningsStream() << "Cannot find no fork location addr for '"
                                       << cfgKey + ".startAddr." + noForkLocation + ".startAddr"
                                       << "'\n";
            exit(-1);
        }
        // record
        disallowedGWRanges.emplace_back(startAddr, endAddr, 0);
    }
    if (!Range::sortRanges(disallowedGWRanges)) {
        g_s2e->getWarningsStream() << "disallowedGWRanges contains overlap!\n";
        exit(-1);
    }

    // Get noGlobalWriteRanges, where glbal memory writes won't be recorded, such as spin_lock(): symbolizing locks will cause infinite loop.
    std::vector<std::string> noGlobalWriteRanges = config->getListKeys(cfgKey + ".pcRanges");
    for (auto &range: noGlobalWriteRanges) {
        uint64_t startAddr = config->getInt(cfgKey + ".pcRanges." + range + ".startAddr", 0, &ok);
        uint64_t endAddr = config->getInt(cfgKey + ".pcRanges." + range + ".endAddr", 0, &ok);
        bool isBlackList = config->getBool(cfgKey + ".pcRanges." + range + ".isBlackList", false);
        if (!ok || startAddr == 0 || endAddr == 0) {
            g_s2e->getWarningsStream() << "Cannot find no global write range addr for '"
                                       << cfgKey + ".startAddr." + range + "startAddr"
                                       << "'\n";
            exit(-1);
        }
        // record
        if (isBlackList) {
            badPcRanges.emplace_back(startAddr, endAddr, 0);
        } else {
            goodPcRanges.emplace_back(startAddr, endAddr, 0);
        }
    }
    if (!Range::sortRanges(goodPcRanges)) {
        g_s2e->getWarningsStream() << "goodPcRanges contains overlap!\n";
        exit(-1);
    }
    if (!Range::sortRanges(badPcRanges)) {
        g_s2e->getWarningsStream() << "badPcRanges contains overlap!\n";
        exit(-1);
    }

    // Get test pcs,
    std::vector<std::string> testPCs = config->getListKeys(cfgKey + ".testPCs");
    for (auto &testPC: testPCs) {
        uint64_t pc = config->getInt(cfgKey + ".testPCs." + testPC + ".pc", 0, &ok);
        uint reg = config->getInt(cfgKey + ".testPCs." + testPC + ".reg", 0, &ok);
        if (!ok || pc == 0) {
            g_s2e->getWarningsStream() << "Cannot find testPCs for '" << cfgKey + ".testPCs." + testPC << "'\n";
            exit(-1);
        }
        // record
        testPCAndRegs[pc].insert(reg);
        // attach signal
        m_monitor->hookAddress(pc, sigc::mem_fun(*this, &Propagator::onTestPc));
    }

    // Get symbolicPointerForkRanges. PCs inside the range will be allowed to fork even when it's a symbolic pointer.
    std::vector<std::string> symbolicPointerForkPointsList = config->getListKeys(cfgKey + ".symbolicPointerForkPoints");
    for (auto &point: symbolicPointerForkPointsList) {
        uint64_t addr = config->getInt(cfgKey + ".symbolicPointerForkPoints." + point, 0, &ok);
        if (!ok || addr == 0) {
            g_s2e->getWarningsStream() << "Cannot find symbolicPointerForkPoints addr for " << point << "\n";
            exit(-1);
        }
        // record
        symbolicPointerForkPoints.insert(addr);
    }

    // Get symbolicPointerForkRanges. PCs inside the range will be allowed to fork even when it's a symbolic pointer.
    std::vector<std::string> killPointsList = config->getListKeys(cfgKey + ".killPoints");
    for (auto &point: killPointsList) {
        uint64_t addr = config->getInt(cfgKey + ".killPoints." + point, 0, &ok);
        if (!ok || addr == 0) {
            g_s2e->getWarningsStream() << "Cannot find killPoints addr for " << point << "\n";
            exit(-1);
        }
        // record
        m_monitor->hookAddress(addr, sigc::mem_fun(*this, &Propagator::onKillPoint));
    }

    // Get forkOnMemAcc
    forkOnMemAcc = config->getBool(cfgKey + ".forkOnMemAcc", false, &ok);
    if (!ok) {
        g_s2e->getWarningsStream() << "Cannot read forkOnMemAcc\n";
        exit(-1);
    }

    // Get oneByteMemAcc
    oneByteMemAcc = config->getBool(cfgKey + ".oneByteMemAcc", false, &ok);
    if (!ok) {
        g_s2e->getWarningsStream() << "Cannot read oneByteMemAcc\n";
        exit(-1);
    }

    // Get printConcretizationFKG
    printConcretizationFKG = config->getBool(cfgKey + ".printConcretizationFKG", false, &ok);
    if (!ok) {
        g_s2e->getWarningsStream() << "Cannot read printConcretizationFKG\n";
        exit(-1);
    }

    // Get verboseBlockExecutionLog
    verboseBlockExecutionLog = config->getBool(cfgKey + ".verboseBlockExecutionLog", false, &ok);
    if (!ok) {
        g_s2e->getWarningsStream() << "Cannot read verboseBlockExecutionLog\n";
        exit(-1);
    }

    // Get concreteExecTimeout
    concreteExecTimeout = config->getInt(cfgKey + ".concreteExecTimeout", 0, &ok);
    if (!ok) {
        g_s2e->getWarningsStream() << "Cannot read concreteExecTimeout\n";
        exit(-1);
    }

    // Get loopDetectionRange
    loopDetectionRange = config->getInt(cfgKey + ".loopDetectionRange", 10, &ok);
    if (!ok) {
        g_s2e->getWarningsStream() << "Cannot read loopDetectionRange\n";
        exit(-1);
    }
    if (loopDetectionRange < 1) {
        g_s2e->getWarningsStream() << "loopDetectionRange must >= 1\n";
        exit(-1);
    }


    // Get loopDetectionTimes
    loopDetectionTimes = config->getInt(cfgKey + ".loopDetectionTimes", 10, &ok);
    if (!ok) {
        g_s2e->getWarningsStream() << "Cannot read loopDetectionTimes\n";
        exit(-1);
    }
    if (loopDetectionTimes < 1) {
        g_s2e->getWarningsStream() << "loopDetectionTimes must >= 1\n";
        exit(-1);
    }

    // Get concreteExecTimeout
    blockExecTimeout = config->getInt(cfgKey + ".blockExecTimeout", 0, &ok);
    if (!ok) {
        g_s2e->getWarningsStream() << "Cannot read blockExecTimeout\n";
        exit(-1);
    }

    // Get unconditionalFork
    unconditionalFork = config->getBool(cfgKey + ".unconditionalFork", false, &ok);
    if (!ok) {
        g_s2e->getWarningsStream() << "Cannot read unconditionalFork\n";
        exit(-1);
    }
    if (unconditionalFork) {
        s2e()->getExecutor()->alwaysForkWithNoConcolicUpdates = true;
    } else {
        s2e()->getExecutor()->alwaysForkWithNoConcolicUpdates = false;
    }

    currentTimeout = config->getInt(cfgKey + ".initSolverTimeout", 5000, &ok);
    if (!ok || currentTimeout < 0) {
        g_s2e->getWarningsStream() << "Cannot read initTimeout or value is wrong\n";
        exit(-1);
    }
//    klee::SolverManager::solver()->setTimeout(currentTimeout);

    timeoutStatePercentage = config->getInt(cfgKey + ".timeoutStatePercentage", 20, &ok);
    if (!ok || timeoutStatePercentage > 100 || timeoutStatePercentage < 0) {
        g_s2e->getWarningsStream() << "Cannot read timeoutStatePercentage or value is wrong\n";
        exit(-1);
    }

    minSolverTimeout = config->getInt(cfgKey + ".minSolverTimeout", 0, &ok);
    if (!ok || minSolverTimeout < 0) {
        g_s2e->getWarningsStream() << "Cannot read minSolverTimeout or value is wrong\n";
        exit(-1);
    }

    feedBackScale = config->getInt(cfgKey + ".feedBackScale", 1, &ok);
    if (!ok || feedBackScale < 1) {
        g_s2e->getWarningsStream() << "Cannot read feedBackScale or value is wrong\n";
        exit(-1);
    }

    _8ByteAtEntryPc = config->getInt(cfgKey + ".magicNum", 0, &ok);
    if (!ok) {
        g_s2e->getWarningsStream() << "magicNum is not provided\n";
    }

    stackStart = config->getInt(cfgKey + ".stackStart", 0, &ok);
    if (!ok) {
        g_s2e->getWarningsStream() << "stackStart is not provided\n";
    } else {
        stackEnd = config->getInt(cfgKey + ".stackEnd", 0, &ok);
        if (!ok || stackEnd == 0 || stackEnd <= stackStart) {
            g_s2e->getWarningsStream() << "stackEnd is wrong\n";
        }
    }

    platModelString = config->getString(cfgKey + ".platModel", "", &ok);
    if (!ok) {
        g_s2e->getWarningsStream() << "Cannot read platModel\n";
        exit(-1);
    }

    // init pid controller
    if (!solverTimeoutPidController) {
        solverTimeoutPidController = new PIDController(1.0, 0.01, 0.05);
    }

    // Init the model
    auto modelString = config->getString(cfgKey + ".model", "", &ok);
    if (!ok) {
        g_s2e->getWarningsStream() << "Cannot read model\n";
        exit(-1);
    }

    if (modelString == "Kernel44UDPModel") {
        model = new Kernel44UDPModel(this);
    } else if (modelString == "Kernel48TCPModel") {
        model = new Kernel48TCPModel(this);
    } else if (modelString == "Kernel310TCPModel") {
        model = new Kernel310TCPModel(this);
    } else if (modelString == "Kernel6132TCPModel") {
        model = new Kernel6132TCPModel(this);
    } else if (modelString == "Kernel6132TCPModelWithOption") {
        model = new Kernel6132TCPModelWithOption(this);
    } else if (modelString == "Kernel6132UDPModel") {
        model = new Kernel6132UDPModel(this);
    } else if (modelString == "WindowsServerTCPModel") {
        model = new WindowsServerTCPModel(this);
    } else if (modelString == "FreeBSDTCPModel") {
        model = new FreeBSDTCPModel(this);
    } else if (modelString == "LWIPTCPModel") {
        model = new LWIPTCPModel(this);
    } else {
        g_s2e->getWarningsStream() << "Invalid model: " << modelString << "! Exiting...\n";
        exit(-1);
    }


    // init platform model
    if (platModelString == "X86_64LinuxKernelModel") {
        platModel = new X86_64LinuxKernelModel(this);
    } else if (platModelString == "NTKernelModel") {
        platModel = new NTKernelModel(this);
    } else if (platModelString == "FreeBSDKernelModel") {
        platModel = new FreeBSDKernelModel(this);
    } else if (platModelString == "X86_64LinuxUserSpaceModel") {
        platModel = new X86_64LinuxUserSpaceModel(this);
    } else {
        g_s2e->getWarningsStream() << "Invalid platform model! Exiting...\n";
        exit(-1);
    }


    // Hook init
    for (const auto &initPoint: model->entryPoints) {
        m_monitor->hookAddress(initPoint, sigc::mem_fun(*this, &Propagator::onEntryFunction));
    }
    // Hook output
    for (const auto &outputPoint: model->outputPoints) {
        m_monitor->hookAddress(outputPoint, sigc::mem_fun(*this, &Propagator::onOutputFunction));
    }

    // For loop detection
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(sigc::mem_fun(*this, &Propagator::onTranslateBlockStart));

/*
    // debug only. disabled for cleaner log
//    m_monitor->hookAddress(0xffffffff81128e90, sigc::mem_fun(*this, &Propagator::onMallocFunction));
//    m_monitor->hookAddress(0xffffffff81117720, sigc::mem_fun(*this, &Propagator::onMallocFunction));
//    m_monitor->hookAddress(0xffffffff81129440, sigc::mem_fun(*this, &Propagator::onMallocFunction));


//    m_monitor->hookAddress(0xffffffff812b70e0, sigc::mem_fun(*this, &Propagator::onKillPoint)); // vsprintf()
//    m_monitor->hookAddress(0xffffffff812b59a0, sigc::mem_fun(*this, &Propagator::onKillPoint)); // number()

//    m_monitor->hookAddress(0xffffffff8162fc2c,
//                           sigc::mem_fun(*this, &Propagator::onOutputFunction)); // tcp_output.c:950c

//





    // Hook engine shutdown to check the dependency on the secret
    s2e()->getCorePlugin()->onEngineShutdown.connect(
            sigc::mem_fun(*this, &Propagator::onEngineShutdown));
            */
}


void Propagator::onMallocFunction(S2EExecutionState *state, uint64_t pc) {
    if (inited) {
        getDebugStream(state) << "onMallocFunction, pc=" << hexval(pc) << "\n";
    }
}

void Propagator::onKillPoint(S2EExecutionState *state, uint64_t pc) {
    if (inited) {
        if (platModel->onKillPoint(state, pc)) {
            killIllegalState(state, "kernel panic (kill point), kill state", FKP_KILL_PANIC);
        }
    }
}

void Propagator::printFKGForAddedConstraint(S2EExecutionState *state, const klee::ref<klee::Expr> &e) {
    auto stateId = state->getID();
    auto fk0 = s2e()->fetchAndIncrementForkingEdgeId();
    auto fk1 = s2e()->fetchAndIncrementForkingEdgeId();
    auto fromFkid = forkedFrom.at(stateId);
    auto owner = (unconditionalFork ? 0 : pathOwner[stateId]);
    forkedFrom[stateId] = fk0;
    // continuation
    std::stringstream ss;
    ss << "[FKG],pc=" << hexval(state->regs()->getPc()) << ",fkid=" << hexval(fromFkid) << ",fk0=" << hexval(fk0)
       << ",fk1=" << hexval(fk1) << ",owner=" << (uint) owner << ",C=\n" << dumpSingleQueryString(state, e);
    getDebugStream(state) << ss.str() << "\n";
    // right side set to kill
    std::stringstream ss1;
    ss1 << "[FKG],pc=" << hexval(state->regs()->getPc()) << ",fkid=" << hexval(fk1) << ",fk0="
        << hexval(FKP_KILL_NA)
        << ",fk1=" << hexval(FKP_KILL_NA) << ",owner=" << (uint) owner << ",C=null\n";
    getDebugStream(state) << ss1.str() << "\n";
}

bool Propagator::addConstraint(S2EExecutionState *state, const klee::ref<klee::Expr> &e, const std::string &reason) {
    if (state->addConstraint(e, true)) {
        getDebugStream(state) << "Adding constraints: reason " << reason << "\n";
        printFKGForAddedConstraint(state, e);
        return true;
    } else {
        getDebugStream(state) << "error adding constraint\n";
        return false;
    }
}

uint64_t
Propagator::readAndConcretizeMemory64(S2EExecutionState *state, uint64_t addr, bool &err, const std::string &reason) {
    err = false;
    uint64_t ret;
    // symbolic value
    auto retExpr = state->mem()->read(addr, sizeof(uint64_t) * 8);
    // concrete value
    if (!state->mem()->read(addr, &ret, sizeof(uint64_t))) {
        err = true;
        return 0;
    }
    if (!isa<klee::ConstantExpr>(retExpr)) {
        addConstraint(state, klee::EqExpr::create(retExpr, klee::ConstantExpr::create(ret, sizeof(uint64_t) * 8)),
                      "readAndConcretizeMemory64: " + reason + ", addr=" + hexval(addr).str());
    }
    return ret;
}

uint32_t
Propagator::readAndConcretizeMemory32(S2EExecutionState *state, uint64_t addr, bool &err, const std::string &reason) {
    err = false;
    uint32_t ret;
    // symbolic value
    auto retExpr = state->mem()->read(addr, sizeof(uint32_t) * 8);
    // concrete value
    if (!state->mem()->read(addr, &ret, sizeof(uint32_t))) {
        err = true;
        return 0;
    }
    if (!isa<klee::ConstantExpr>(retExpr)) {
        addConstraint(state, klee::EqExpr::create(retExpr, klee::ConstantExpr::create(ret, sizeof(uint32_t) * 8)),
                      "readAndConcretizeMemory32: " + reason + ", addr=" + hexval(addr).str());
    }
    return ret;
}

uint16_t
Propagator::readAndConcretizeMemory16(S2EExecutionState *state, uint64_t addr, bool &err, const std::string &reason) {
    err = false;
    uint16_t ret;
    // symbolic value
    auto retExpr = state->mem()->read(addr, sizeof(uint16_t) * 8);
    // concrete value
    if (!state->mem()->read(addr, &ret, sizeof(uint16_t))) {
        err = true;
        return 0;
    }
    if (!isa<klee::ConstantExpr>(retExpr)) {
        addConstraint(state, klee::EqExpr::create(retExpr, klee::ConstantExpr::create(ret, sizeof(uint16_t) * 8)),
                      "readAndConcretizeMemory16: " + reason + ", addr=" + hexval(addr).str());
    }
    return ret;
}

uint8_t
Propagator::readAndConcretizeMemory8(S2EExecutionState *state, uint64_t addr, bool &err, const std::string &reason) {
    err = false;
    uint8_t ret;
    // symbolic value
    auto retExpr = state->mem()->read(addr, sizeof(uint8_t) * 8);
    // concrete value
    if (!state->mem()->read(addr, &ret, sizeof(uint8_t))) {
        err = true;
        return 0;
    }
    if (!isa<klee::ConstantExpr>(retExpr)) {
        addConstraint(state, klee::EqExpr::create(retExpr, klee::ConstantExpr::create(ret, sizeof(uint8_t) * 8)),
                      "readAndConcretizeMemory8: " + reason + ", addr=" + hexval(addr).str());
    }
    return ret;
}

//GlobalWrite2 Propagator::getOutputSummaryTcpLinux310(llvm::raw_ostream &s, S2EExecutionState *state, uint64_t pc) {
//
//    uint64_t skbPtr;
//    auto isCon = state->regs()->read(CPU_OFFSET(regs[R_EDI]), &skbPtr, 8, false);    // 8 bytes
//    if (!isCon) {
//        auto sym = state->regs()->read(CPU_OFFSET(regs[R_EDI]), klee::Expr::Int64);
//        if (state->regs()->read(CPU_OFFSET(regs[R_EDI]), &skbPtr, 8, true)) {
//            s << "concretizing skbPtr on output function pc=" << hexval(pc) << ", skb=" << hexval(skbPtr) << "\n";
//            addConstraint(state, klee::EqExpr::create(sym, klee::ConstantExpr::create(skbPtr, klee::Expr::Int64)));
//        } else {
//            s << "Failed to concretize skbPtr on output function pc=" << hexval(pc) << ", skb=\n"
//              << state->regs()->read(CPU_OFFSET(regs[R_EDI]), klee::Expr::Int64);
//            return {};
//        }
//    }
//
//    bool err = false;
//    const uint64_t headOffset = 216;    // &(skb->head) - skb
//    auto headPtr = readAndConcretizeMemory<uint64_t>(state, skbPtr + headOffset, err);   // skb->head
//    if (err) {
//        s << "Failed to access skb->head on output function pc=" << hexval(pc) << ", &(skb->head)=\n"
//          << hexval(skbPtr + headOffset);
//        return {};
//    }
//
//
//    const uint64_t transportHdrOffset = 192;    // &(skb->transport_header) - skb
//    auto transportPtr = readAndConcretizeMemory<uint64_t>(state, skbPtr + transportHdrOffset,
//                                                          err);   // skb->transport_header
//    if (err) {
//        s << "Failed to access skb->transportPtr on output function pc=" << hexval(pc) << ", &(skb->transportPtr)=\n"
//          << hexval(skbPtr + transportHdrOffset);
//        return {};
//    }
//
//    uint64_t tcpHdrPtr = headPtr + transportPtr;  // skb->head + skb->transport_header
//    const uint64_t tcpHdrSize = 20;
//    auto tcpHdr = extendedRead(state, tcpHdrPtr, tcpHdrSize * 8); // 160 bits
//    if (tcpHdr.isNull()) { // 8 bytes
//        s << "Failed to access *(skb->head + skb->transportPtr) on output function pc=" << hexval(pc)
//          << ", skb->head + skb->transportPtr=\n"
//          << hexval(tcpHdrPtr);
//        return {};
//    }
//
//    auto tmp = GlobalWrite2();
//    tmp.size = tcpHdrSize;
//    tmp.isOutput = true;
//    tmp.pc = pc;
//    tmp.summary = tcpHdr;
//    tmp.cAddr = tcpHdrPtr;
//    tmp.stateID = state->getID();
//    tmp.isPcPrecise = true;
//
//    return tmp;
//}


void Propagator::onOutputFunction(S2EExecutionState *state, uint64_t pc) {
//    getDebugStream(state) << "Propagator::onOutputFunction\n";
    if (inited) {
        getDebugStream(state) << "got output: " << hexval(pc) << "\n";

        auto tmp = std::make_shared<GlobalWrite2>(model->onOutputFunction(state, pc));
        if (tmp->isOutput) {
            // things are going normally
            // store
            // TODO: we just allow one output in one state, possible multiple outputs (e.g., sending 2 vs 3 packets) also differ
            // Above seems like to be impossible since we only process one packet per state
            if (globalWrites[state->getID()].find(tmp->cAddr) != globalWrites[state->getID()].end() &&
                globalWrites[state->getID()].find(tmp->cAddr)->second->isOutput) {
                getDebugStream(state) << "WARN: found multi output points old="
                                      << hexval(globalWrites[state->getID()][tmp->cAddr]->cAddr) << ", new="
                                      << hexval(tmp->cAddr) << "\n";
            }
            tmp->forkedFromID = forkedFrom[tmp->stateID];
            globalWrites[state->getID()][tmp->cAddr] = tmp;
        }

        s2e()->getExecutor()->terminateState(*state, "reached output point, kill state");
    }
}

void Propagator::cleanMemory(S2EExecutionState *state) {
    globalWrites.erase(state->getID());
    forkPoints.erase(state->getID());
    pathOwner.erase(state->getID());
    forceKilledStates.erase(state->getID());
    forkedFrom.erase(state->getID());
    noSymbolizeMem.erase(state->getID());
    pcAtInterrupt.erase(state->getID());
    allowedSymbolicAddressPC.erase(state->getID());
}

void Propagator::onStateKill(S2EExecutionState *state) {
    static std::unordered_map<uint8_t, uint64_t> widthConstantTable = {{8,  22},
                                                                       {16, 22222},
                                                                       {32, 2222222222L},
                                                                       {64, 2222222222222222222L}};
    // output path constraints
    // TODO: If we know the tree of the constraint, we can do some optimization when generating the inputs (e.g., two paths under the contradicting children of the root will not lead to a valid input).
//    getDebugStream(state) << "Propagator::onStateKill\n";
    if (s2e()->getExecutor()->isLoadBalancing()) {
        // if in load balancing, we only clean the memory
        cleanMemory(state);
    } else {
        auto forceKilled = (forceKilledStates.find(state->getID()) != forceKilledStates.end());

        if (!forceKilled) {
            auto i = 0;
            if (!unconditionalFork) {
                // disable PC msg. no use as of now. fkg is more useful.
//                for (const auto &c: state->constraints().getConstraintSet()) {
                std::stringstream ss;
                ss << (forceKilled ? "[FKPCFK],owner=" : "[PC],owner=") << uint(pathOwner[state->getID()]) << "\n";
                getDebugStream(state) << ss.str() << "\n";
//                }
            }
            // output global writes. didn't consider symbolic addresses
            i = 0;
            for (const auto &gw: globalWrites[state->getID()]) {
                std::stringstream ss;
                ss << (forceKilled ? "[FKGWFK]," : "[GW],") << "addr=" << hexval(gw.second->cAddr) << ",out=";
                if (gw.second->isOutput) {
                    ss << "T,";
                } else {
                    ss << "F,";
                }
                ss << "varname=,sym=F,id=" << i++ << ",size=" << int(gw.second->size) << ",pc=" << hexval(gw.second->pc)
                   << ",staledby=0,fromFkid=" << hexval(gw.second->forkedFromID) << ",summary=";
                if (isa<klee::ConstantExpr>(gw.second->summary)) {
                    ss << dumpSingleQueryString(state, cast<klee::ConstantExpr>(gw.second->summary));
                } else {
                    auto summary = dumpSingleQueryString(state, klee::EqExpr::create(gw.second->summary,
                                                                                     klee::ConstantExpr::create(
                                                                                             widthConstantTable[gw.second->summary->getWidth()],
                                                                                             gw.second->summary->getWidth())));
                    ss << "\n" << summary;
                }
                getDebugStream(state) << ss.str() << "\n";
            }
        }

        // generate [FKG] msg
        if (!forceKilled) {
            getDebugStream(state) << "[FKG],pc=" << hexval(state->regs()->getPc()) << ",fkid="
                                  << hexval(forkedFrom[state->getID()]) << ",fk0=" << hexval(FKP_TERM) << ",fk1="
                                  << hexval(FKP_TERM) << ",owner=" << (uint) (pathOwner[state->getID()]) << ",C=null\n";
        } else {
            auto childFkidStr = hexval(forceKilledStates.at(state->getID()));
            getDebugStream(state) << "[FKG],pc=" << hexval(state->regs()->getPc()) << ",fkid="
                                  << hexval(forkedFrom[state->getID()]) << ",fk0=" << childFkidStr << ",fk1="
                                  << childFkidStr << ",owner=" << (uint) (pathOwner[state->getID()]) << ",C=null\n";
        }
//        localFinishedPathCount++;
//        updateSolverTimeout(state);
        if (!unconditionalFork && !forceKilled) {
            if (pathOwner[state->getID()] == model->victimOwner || pathOwner[state->getID()] == model->attackerOwner) {
                s2e()->fetchAndIncreaseStatesCount(pathOwner[state->getID()], weakOwner, finishedStatesCountByOwner,
                                                   &timeoutStateCounts, false);
                getDebugStream(state) << "OwnerCount[" << (uint) pathOwner[state->getID()] << "]="
                                      << finishedStatesCountByOwner[pathOwner[state->getID()] - 1] << "\n";
            }
        }
        // output forking points
//    i = 0;
//    for (auto fkp: forkPoints[state->getID()]) {
//        getDebugStream(state) << "[FK],id=" << i++ << "," << hexval(fkp) << "\n";
//    }
        // release memory
        cleanMemory(state);
    }
}

void Propagator::replaceAll(std::string &str, const std::string &from, const std::string &to) {
    if (from.empty())
        return;
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
    }
}

// The expr must be a boolean expression. For GW print requests, we need to add a fake ==0.
std::string Propagator::dumpSingleQueryString(S2EExecutionState *state, const klee::ref<klee::Expr> &expr) {
    if (isa<klee::ConstantExpr>(expr)) {
        std::string ret;
        cast<klee::ConstantExpr>(expr)->toString(ret, 16);
        return "0x" + ret;
    } else {
        klee::ExprSMTLIBPrinter printer;
//    printer.setHumanReadable(false);
        std::string ret;
        llvm::raw_string_ostream ss(ret);
        printer.setOutput(ss);
        auto tmpMgr = klee::ConstraintManager();
        tmpMgr.addConstraint(expr);
        klee::Query query(tmpMgr, klee::ConstantExpr::alloc(0, klee::Expr::Bool));
        printer.setQuery(query);
        printer.generateOutput();
        ss.flush();
//    replaceAll(ret, "\n", "");
        return ret;
    }
}


//std::string Propagator::dumpQueryString(S2EExecutionState *state, klee::ConstraintManager &mgr) {
//
//}

std::string Propagator::dumpSetValue(S2EExecutionState *state) {
    klee::ExprSMTLIBPrinter printer;
//    printer.setHumanReadable(false);
    std::string ret;
    llvm::raw_string_ostream ss(ret);
    printer.setOutput(ss);

    // Extract symbolic objects
    klee::ArrayVec symbObjects;
    for (auto &symbolic: state->symbolics) {
        symbObjects.push_back(symbolic);
    }
    printer.setArrayValuesToGet(symbObjects);

//    klee::Query query(state->constraints(), klee::ConstantExpr::alloc(0, klee::Expr::Bool));
//    printer.setQuery(query);

    printer.generateOutput();
//    replaceAll(ret, "\n", "");

    return ret;
}

void Propagator::onEntryFunction(S2EExecutionState *state, uint64_t pc) {
    // TODO: if multiple packets (like SymTCP) are supported, secrets should be symbolized everytime the entry func is called
    // BUG: currently only one entryFunc is supported. Multiple entryfunc should have different stack base and should be inited separately
    // make symbols and find the bottom of the stack (growing downwards)
//    getDebugStream(state) << "Propagator::onEntryFunction\n";

    if (!inited) {
        // This allows plat model to check if the current process is the target.
        if (!platModel->onEntryFunction(state, pc)) {
            return;
        }

        m_tracer->enable(state);
        // symbolize secrets
        for (auto const &secret: secrets) {
            // symbolize the secret, only once
            // TODO: input should also be symbolized without Zhongjie's SymTCP
            if (Range::search(disallowedGWRanges, secret.second.addr)) {
                getDebugStream(state) << "BUG: Secret " << secret.second.name
                                      << " is not symbolized due to overlapping with no forking point\n";
                exit(-1);
            }
            makeSymbolic(state, secret.second.addr, secret.second.len, secret.second.name);
            getDebugStream(state) << " symbolize secret " << secret.second.description << "\n";
        }

        /*
        // symbolize global variables
        for (auto const &globalVar: globalVars) {
            // symbolize the global vars, only once
            bool illegalGV = false;
            if (Range::search(disallowedGWRanges, globalVar.second.addr)) {
                illegalGV = true;
                getDebugStream(state) << "GV " << globalVar.second.name
                                      << " is not symbolized due to overlapping with no forking point\n";
            }
            if (!illegalGV) {
                makeSymbolic(state, globalVar.second.addr, globalVar.second.len, globalVar.second.name);
                getDebugStream(state) << " symbolize global var" << globalVar.second.description << "\n";
            }
        }
         */


        // Hook mem write access functions. Both are required to get all mem accesses
        s2e()->getCorePlugin()->onConcreteDataMemoryAccess.connect(
                sigc::mem_fun(*this, &Propagator::onConcreteDataMemoryAccess));
        s2e()->getCorePlugin()->onAfterSymbolicDataMemoryAccess.connect(
                sigc::mem_fun(*this, &Propagator::onAfterSymbolicDataMemoryAccess));
        s2e()->getCorePlugin()->onBeforeSymbolicDataMemoryAccess.connect(
                sigc::mem_fun(*this, &Propagator::onBeforeSymbolicDataMemoryAccess));

        // hook state kill to get state constraints and output
        s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &Propagator::onStateKill));
        // hook state fork to copy the global var array
        s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &Propagator::onStateFork));
        // hook before state fork to make it not fork too much when on loop
        s2e()->getCorePlugin()->onStateForkDecide.connect(sigc::mem_fun(*this, &Propagator::onStateForkDecide));
        // stop symbolic pointers from forking
        s2e()->getCorePlugin()->onBeforeSymbolicAddress.connect(
                sigc::mem_fun(*this, &Propagator::onBeforeSymbolicAddress));
        s2e()->getCorePlugin()->onSymbolicAddress.connect(sigc::mem_fun(*this, &Propagator::onSymbolicAddress));
        // deal with timeout events
        s2e()->getCorePlugin()->onTimeout.connect(sigc::mem_fun(*this, &Propagator::onTimeout));
        // exceptions
        s2e()->getCorePlugin()->onException.connect(sigc::mem_fun(*this, &Propagator::onException));


        // init fork point
        forkPoints[state->getID()] = std::vector<uint64_t>();
        forkPoints[state->getID()].push_back(state->regs()->getPc());

        // init prev forking pc
        forkedFrom[state->getID()] = FKP_ROOT;

        // init ipowner
        pathOwner[state->getID()] = model->defaultOwner;

        lastForkTime = time(nullptr);
        lastForkTimeState = state->getID();

        // Hook termination
        for (const auto &terminatePoint: model->terminatePoints) {
            m_monitor->hookAddress(terminatePoint, sigc::mem_fun(*this, &Propagator::terminateState));
        }

        inited = true;
    }

    model->onEntryFunction(state, pc);
    /* add the init state info
    int id = state->getID();
    if (stateInfos[id] == nullptr) {
        auto s = new StateInfo; // cleaned when var states destructs
        s->id = id;
        stateInfos[id] = s;
    }*/

}

bool Propagator::traverseConstraintSecretCheck(const klee::ref<klee::Expr> &e, std::string *secretName) {
    if (e.isNull()) {
        return false;
    }

    for (unsigned i = 0; i < e->getNumKids(); i++) {
        if (traverseConstraintSecretCheck(e->getKid(i), secretName)) {
            return true;
        }
    }

    auto s = getSymName(e);
    // since the symname includes the index like rcv_nxt_0_, we need to remove the last 3 chars
    if (s.size() >= 3) {
        s = s.substr(0, s.size() - 3);
        // Check whether an atom expression contains the secret symval
        auto sit = secrets.find(s);
        if (sit != secrets.end()) {
            *secretName = sit->second.name;
            return true;
        }
    }

    return false;
}


std::set<klee::ref<klee::Expr>> *Propagator::traverseConstraint(const klee::ref<klee::Expr> &e) {
    if (e.isNull()) {
        return nullptr;
    }
    auto res = new std::set<klee::ref<klee::Expr>>; // to be freed by caller
    for (unsigned i = 0; i < e->getNumKids(); i++) {
        auto tmp = traverseConstraint(e->getKid(i));
        if (tmp != nullptr) {
            res->insert(tmp->begin(), tmp->end());
            delete tmp;
        }
    }
    res->insert(e);
    return res;
}

void Propagator::onEngineShutdown() {
    /*// Check control dependency on secret
    for (auto state : stateInfos) {
        // classify the states according to secret related constraints
        secretRelatedConstraints[state.second->secretRelatedConstraints].insert(state.second);
    }
    // filter global writes


    int i = 0;
    for (auto it : secretRelatedConstraints) {
        getDebugStream() << "class " << i++ << ": ";
        for (auto sinfo:it.second) {
            getDebugStream() << sinfo->id << ", ";
        }
        getDebugStream() << "\n";
    }

    i = 0;
    for (auto it : globalWrites) {
        getDebugStream() << "globalWrites " << i++ << ": " << it.second->addr.con;
        for (auto s:it.second->allStates) {
            getDebugStream() << s->id << ", ";
        }
        getDebugStream() << "\n";
    }

    sleep(10);
    getDebugStream() << "length=" << stateInfos.size() << "\n";
    // Check data dependency on secret*/
}

// note that the size of newState is always 2.
void Propagator::onStateFork(S2EExecutionState *oldState, const std::vector<S2EExecutionState *> &newState,
                             const std::vector<klee::ref<klee::Expr>> &newCond) {
    auto pc = oldState->regs()->getPc();
    if (allowedSymbolicAddressPC[oldState->getID()] != pc) {
        forkPoints[oldState->getID()].push_back(pc);
    }
    std::stringstream ss;
    getForkingSeq(oldState->getID(), ss);
    getDebugStream(oldState) << "Forking path: " << ss.str() << "\n";
    if (inited) {
        auto oldIpOwner = pathOwner[oldState->getID()];
        assert(newState.size() == 2);
        s2e::S2EExecutionState *newOwnerTimeoutStates[2] = {nullptr, nullptr};
        for (auto state: newState) {
            if (state->getID() != oldState->getID()) {
                // copy state-related info
                if (state->getID() != oldState->getID()) {
                    parentState[state->getID()] = oldState->getID();
                }
                if (!unconditionalFork) {
                    // just not useful and it's a waste of memory
                    globalWrites[state->getID()] = globalWrites[oldState->getID()];
                }
                auto tmp = std::vector<uint64_t>();
                // keep the last loopDetectionRange fork points to save memory
                const auto &oldForkPoints = forkPoints[oldState->getID()];
                for (auto i = 0; i < loopDetectionRange * loopDetectionTimes && i < oldForkPoints.size(); i++) {
                    tmp.push_back(oldForkPoints.at(oldForkPoints.size() - 1 - i));
                }
                forkPoints[state->getID()] = tmp;
                noSymbolizeMem[state->getID()] = noSymbolizeMem[oldState->getID()];
            }

            // process ip owner
            if (!unconditionalFork) {
                auto newOwner = model->getNewStateOwner(oldState, state, newCond, this, oldIpOwner);
                if (newOwner != 0) {
                    pathOwner[state->getID()] = newOwner;
                } else {
                    // Get new owner timeout
                    pathOwner[state->getID()] = oldIpOwner;
                    if (!newOwnerTimeoutStates[0]) {
                        newOwnerTimeoutStates[0] = state;
                    } else {
                        newOwnerTimeoutStates[1] = state;
                    }
                }
            }
            // output
            getDebugStream(state) << "Forked from " << oldState->getID() << ", " << state->concolics->bindings.size()
                                  << " concolic bindings \n";
        }
        // generate [FKG] msg
        auto fk0 = s2e()->fetchAndIncrementForkingEdgeId();
        auto fk1 = s2e()->fetchAndIncrementForkingEdgeId();
        std::stringstream ss1;
        ss1 << "[FKG],pc=" << hexval(pc) << ",fkid=" << hexval(forkedFrom[oldState->getID()])
            << ",fk0=" << hexval(fk0) << ",fk1=" << hexval(fk1) << ",owner=" << (uint) oldIpOwner << ",C=\n"
            << dumpSingleQueryString(oldState, newCond[0]); // cond[0] is s0's cond
        getDebugStream(oldState) << ss1.str() << "\n";
        forkedFrom[newState[0]->getID()] = fk0;
        forkedFrom[newState[1]->getID()] = fk1;
        if (concreteExecTimeout == 1 && lastForkTime > 0 && lastForkTimeState == oldState->getID()) {
            getDebugStream(oldState) << "[SAMCE]," << time(nullptr) - lastForkTime << "\n";
        }
        lastForkTime = time(nullptr);
        lastForkTimeState = oldState->getID();
        // Kill those with unknown owners
        for (const auto &state: newOwnerTimeoutStates) {
            if (state) {
                onTimeout(state, CorePlugin::TimeoutReason::SOLVER);
            }
        }
    }
}

bool
Propagator::symbolizeMemory(S2EExecutionState *state, unsigned int flags, uint64_t cVirtAddr, uint8_t size,
                            const std::string &nameStr, std::vector<klee::ref<klee::Expr>> *varData,
                            std::string *varName) {
    assert((!varName || varName->empty()) && "we can't guarantee one call only generates one symbol!");
//    getDebugStream(state) << "[DBGSY]: symbolize " << hexval(cVirtAddr) << ", size=" << uint(size) << "\n";
    if (oneByteMemAcc && size > 1) {
        std::vector<klee::ref<klee::Expr>> tmpVarData;
        for (uint8_t i = 0; i < size; i++) {
            if (!symbolizeMemory(state, flags, cVirtAddr + i, 1, nameStr, &tmpVarData, varName)) {
                return false;
            }
        }
        if (varData != nullptr) {
            varData->push_back(tmpVarData[0]);
        }
        return true;
    }
    auto pc = state->regs()->getPc();
    auto stateId = state->getID();
    // Check for nosymbolizemem
    bool needSmash = false;
    for (uint8_t i = 0; i < size; i++) {
        if (noSymbolizeMem[stateId].find(cVirtAddr + i) != noSymbolizeMem[stateId].end()) {
            needSmash = true;
            break;
        }
    }
    if (needSmash) {
        for (uint8_t i = 0; i < size; i++) {
            if (noSymbolizeMem[stateId].find(cVirtAddr + i) == noSymbolizeMem[stateId].end()) {
                getDebugStream(state) << "Smashed mem acc " << hexval(cVirtAddr) << ", off " << (uint) i << ", size "
                                      << uint(size) << "\n";
                assert(!varData);
                if (!symbolizeMemory(state, flags, cVirtAddr + i, 1, nameStr, varData, varName)) {
                    return false;
                }
            }
        }
        return true;
    }

    // check if local copy is enough
    bool needUpdate = false;
    for (uint8_t i = 0; i < size; i++) {
        if (symbolizedGlobalMem.find(cVirtAddr + i) == symbolizedGlobalMem.end()) {
            needUpdate = true;
            break;
        }
    }
    if (needUpdate) {
        if (!s2e()->syncSymbolizedGlobalMemAccs(symbolizedGlobalMem, cVirtAddr, size, pc, state, true, nameStr)) {
            return false;
        }
//        std::stringstream ss;
//        ss << "symbol table updated:\n";
//        for (const auto &p: symbolizedGlobalMem) {
//            ss << hexval(p.first) << "\t" << int(p.second) << "\n";
//        }
//        getDebugStream(state) << ss.str();
    }


    // do symbolization for current state
    uint64_t lastStartAddr = 0;
    uint64_t startAddr;
    assert((!varData || symbolizedGlobalMem.at(cVirtAddr) == -size) &&
           "we can't guarantee one call only generates one symbol!");
    if (symbolizedGlobalMem.at(cVirtAddr) != -size) {
        if (symbolizedGlobalMem.at(cVirtAddr) > 0) {
            getDebugStream(state) << "Unaligned access among diff states: " << hexval(cVirtAddr) << "@" << (uint) size
                                  << " vs " << hexval(cVirtAddr - symbolizedGlobalMem.at(cVirtAddr)) << "@"
                                  << (uint) -symbolizedGlobalMem.at(cVirtAddr - symbolizedGlobalMem.at(cVirtAddr))
                                  << "\n";
        } else {
            getDebugStream(state) << "Unaligned access among diff states: " << hexval(cVirtAddr) << "@" << (uint) size
                                  << " vs " << hexval(cVirtAddr) << "@" << (uint) -symbolizedGlobalMem.at(cVirtAddr)
                                  << "\n";
        }
    }
    for (uint8_t i = 0; i < size; i++) {
        auto curAddr = cVirtAddr + i;
        // The symbolizing target should be in the global symbolization schedule.
        if (symbolizedGlobalMem.at(curAddr) > 0) {
            startAddr = curAddr - symbolizedGlobalMem[curAddr];
        } else {
            startAddr = curAddr;
        }
        if (startAddr != lastStartAddr) {
            assert(symbolizedGlobalMem[startAddr] < 0);
            std::stringstream ss1;
            ss1 << (((flags & MEM_TRACE_FLAG_WRITE) != 0) ? "gw_" : "gr_") << hexval(startAddr);
//            getDebugStream(state) << "[DBG2]:" << hexval(cVirtAddr) << "," << int(symbolizedGlobalMem[cVirtAddr])
//                                  << uint(size) << "," << uint(i) << ","
//                                  << hexval(startAddr) << "," << int(symbolizedGlobalMem[startAddr]) << ","
//                                  << hexval(lastStartAddr) << "," << int(symbolizedGlobalMem[lastStartAddr]) << "\n";
            // check if the content is likely to be a pointer


            m_base->makeSymbolic(state, startAddr, -symbolizedGlobalMem[startAddr], ss1.str(), varData, varName);
            // mark as symbolized
            for (auto offset = 0; offset < -symbolizedGlobalMem[startAddr]; offset++) {
                noSymbolizeMem[state->getID()][startAddr + offset] = true;
            }
            lastStartAddr = startAddr;
        }
    }
    return true;
}

void Propagator::onMemoryWrite(S2EExecutionState *state, uint64_t cVirtAddr, uint8_t size) {
    if (oneByteMemAcc && size > 1) {
        for (uint8_t i = 0; i < size; i++) {
            onMemoryWrite(state, cVirtAddr + i, 1);
        }
        return;
    }
    auto pc = state->regs()->getPc();
    // check if local copy is enough
    bool needUpdate = false;
    for (uint8_t i = 0; i < size; i++) {
        if (symbolizedGlobalMem.find(cVirtAddr + i) == symbolizedGlobalMem.end()) {
            needUpdate = true;
            break;
        }
    }
    if (needUpdate) {
        // This can't return false as needSymOutput=false
        s2e()->syncSymbolizedGlobalMemAccs(symbolizedGlobalMem, cVirtAddr, size, pc, state, true);
    }
    // build GlobalWrite2 object
    uint64_t lastStartAddr = 0;
    uint64_t startAddr;
    for (uint8_t i = 0; i < size; i++) {
        auto curAddr = cVirtAddr + i;
        // The symbolizing target should be in the global symbolization schedule.
        if (symbolizedGlobalMem.at(curAddr) > 0) {
            startAddr = curAddr - symbolizedGlobalMem[curAddr];
        } else {
            startAddr = curAddr;
        }
        if (startAddr != lastStartAddr) {
            auto symbolSize = -symbolizedGlobalMem[startAddr];
            assert(symbolSize > 0);
            auto tmp = std::make_shared<GlobalWrite2>();
            tmp->stateID = state->getID();
            tmp->cAddr = startAddr;
            tmp->pc = pc;
            tmp->size = symbolSize;
            tmp->summary = state->mem()->read(startAddr, symbolSize * 8);
            tmp->isOutput = false;
            tmp->forkedFromID = forkedFrom[tmp->stateID];
            globalWrites[state->getID()][startAddr] = tmp;
            lastStartAddr = startAddr;
        }
    }
}


void Propagator::onMemoryAccess(bool isConcrete, S2EExecutionState *state, const uint64_t cVirtAddr, unsigned flags,
                                uint8_t size /*in bytes*/, bool oneByteAcc) {
    //test
//    if (state->regs()->getPc() == 0xffffffff816384c6) {
//        getDebugStream(state) << "0xffffffff816384c6 acc " << hexval(cVirtAddr) << "\n";
//    }


    // find global memory writes
    // check if it's global & write
    // TODO: didn't consider symbolic memory write (sym addr)

//    static uint64_t count = 0;
//    if (count++ % 1000000 == 0) {
//        getDebugStream(state) << "visited: " << count / 1000000 << "M times. inited=" << inited << "\n";
//        getDebugStream(state) << "pc=" << hexval(state->regs()->getPc()) << "caddr=" << hexval(cVirtAddr) << "\n";
//        int i = 0;
//        for (auto fkp: forkPoints[state->getID()]) {
//            getDebugStream(state) << "[F],id=" << i++ << "," << hexval(fkp) << "\n";
//        }
//    }


    if (inited && cVirtAddr != 0) {
        auto pc = state->regs()->getPc();

        if (pcAtInterrupt[state->getID()] == pc) {
            // Avoid symbolizing IDT (interrupt table) entries and causing warning of KLEE: WARNING: silently concretizing (instruction: se_do_interrupt_all:   %179 = load i32, i32* %178, align 8) (reason: Read from always concrete memory name:ConcreteCpuRegisters
            return;
        }

        // Remove accesses made by disallowed instructions
        // TODO: Since PC is not precise, we'd better use onInstructionExecution to finish this job to mark the illegal gws
        if (!isPcAllowed(state, pc)) {
            // killIllegalState(state, "kill state due to disallowed pc.", FKP_KILL_DISALLOWED_PC);
            return;
        }

        auto sVal = state->mem()->read(cVirtAddr, size * 8);
        klee::ref<klee::ConstantExpr> cVal;
        if (!sVal.isNull()) {
            if (isa<klee::ConstantExpr>(sVal)) {
                cVal = cast<klee::ConstantExpr>(sVal);
            }
        } else {
            std::stringstream ss;
            ss << "illegal mem acc @ " << hexval(cVirtAddr) << ", pc=" << hexval(pc) << "\n";
            killIllegalState(state, ss.str(), FKP_KILL_ILLEGAL_MEM_ACC);
            return;
        }

        // skip symbolizing pointers
        if (!cVal.isNull() && platModel->isLikelyToBeAPointer(cVal->getZExtValue(), size)) {
            return;
        }

        // No matter when the memory is written, we can't symbolize it again bc the value will be fixed in the current and children states
        if ((flags & MEM_TRACE_FLAG_WRITE) != 0) {
            // we need to record every individual byte we symbolized to notice the unaligned memory access regardless of symbolizing one byte or multiple bytes
            for (auto offset = 0; offset < size; offset++) {
                noSymbolizeMem[state->getID()][cVirtAddr + offset] = true;
            }
        }

        if (platModel->isOutOfStack(cVirtAddr, size, state) && !Range::search(disallowedGWRanges, cVirtAddr, size)) {
            if ((flags & MEM_TRACE_FLAG_WRITE) != 0) {
                onMemoryWrite(state, cVirtAddr, size);
            } else if (forkOnMemAcc) {
                if (!symbolizeMemory(state, flags, cVirtAddr, size)) {
                    killIllegalState(state, "symbol make error", FKP_KILL_SYMBOL_MAKE_ERR);
                    return;
                }
            }
        }
    }
}


void Propagator::onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t virtAddr, uint64_t &val, uint8_t size,
                                            unsigned int flags) {
//    getDebugStream(state) << "onConcreteDataMemoryAccess, pc=" << hexval(state->regs()->getPc()) << ", flags="
//                          << (uint) flags << "\n";
    // Use before for read and use after for write.
    auto isAfter = (flags & MEM_TRACE_FLAG_AFTER) > 0;
    auto isWrite = (flags & MEM_TRACE_FLAG_WRITE) > 0;
    if (!(isAfter ^ isWrite)) {
        onMemoryAccess(true, state, virtAddr, flags, size, oneByteMemAcc);
    }
}

void Propagator::onAfterSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> virtAddr,
                                                 klee::ref<klee::Expr> hostAddr, klee::ref<klee::Expr> val,
                                                 unsigned int flags) {
//    getDebugStream(state) << "onAfterSymbolicDataMemoryAccess, pc=" << hexval(state->regs()->getPc()) << ", flags="
//                          << (uint) flags << "\n";
    // write only
    if ((flags & MEM_TRACE_FLAG_WRITE) != 0) {
        uint64_t cAddr = 0;
        /* Symbolic memory acc won't exist because we concretize them in onSymbolicAddress(). */
        if (isa<klee::ConstantExpr>(virtAddr)) {
            cAddr = cast<klee::ConstantExpr>(virtAddr)->getZExtValue();
        }
        onMemoryAccess(false, state, cAddr, flags, val->getWidth() / 8, oneByteMemAcc);
    }
}

void Propagator::onBeforeSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> vAddr,
                                                  klee::ref<klee::Expr> val, bool isWrite) {
    // read only
//    getDebugStream(state) << "onBeforeSymbolicDataMemoryAccess, pc=" << hexval(state->regs()->getPc()) << ", isWrite="
//                          << isWrite << "\n";
    if (!isWrite) {
//    getDebugStream(state) << "onBeforeSymbolicDataMemoryAccess\n";
        uint64_t cAddr = 0;
        /* Symbolic memory acc won't exist because we concretize them in onSymbolicAddress(). */
        if (isa<klee::ConstantExpr>(vAddr)) {
            cAddr = cast<klee::ConstantExpr>(vAddr)->getZExtValue();
        }
        onMemoryAccess(true, state, cAddr, 0, val->getWidth() / 8, oneByteMemAcc);
    }
}

// It returns the var name matched with user input: no v0_...._0 pre/post fixes
std::string Propagator::getSymName(klee::ref<klee::Expr> value) {
    klee::ReadExpr *revalue;
/*    if (value->getKind() == klee::Expr::Concat) {
        auto *c_value = llvm::cast<klee::ConcatExpr>(value);
        revalue = llvm::cast<klee::ReadExpr>(c_value->getKid(0));
    } else*/ if (value->getKind() == klee::Expr::Read) {
        revalue = llvm::cast<klee::ReadExpr>(value);
    } else {
        return "";
    }
    std::string globalName = revalue->getUpdates()->getRoot()->getRawName();
    return globalName;
}

void Propagator::onTranslateBlockStart(ExecutionSignal *sig, S2EExecutionState *state, TranslationBlock *tb,
                                       uint64_t pc) {
//    if (keepConcrete.find(state->getID()) != keepConcrete.end() && keepConcrete.at(state->getID())) {
//        if (!state->isRunningConcrete()) {
//            state->switchToConcrete();
//            s2e()->getExecutor()->updateConcreteFastPath(state);
//            getDebugStream(state) << "Permanently switch to concrete mode @ pc = " << hexval(pc) << "\n";
//        }
//    } else if (Range::search(goodPcRanges, pc) && !Range::search(badPcRanges, pc)) {
//        if (state->isRunningConcrete()) {
//            state->switchToSymbolic();
//            s2e()->getExecutor()->updateConcreteFastPath(state);
//            getDebugStream(state) << "Switch to symbolic mode @ pc = " << hexval(pc) << "\n";
//        }
//    } else {
//        if (!state->isRunningConcrete()) {
//            state->switchToConcrete();
//            s2e()->getExecutor()->updateConcreteFastPath(state);
//            getDebugStream(state) << "Switch to concrete mode @ pc = " << hexval(pc) << "\n";
//        }
//    }
    sig->connect(sigc::mem_fun(*this, &Propagator::onBlockExecution));
}

void
Propagator::onBlockExecution(S2EExecutionState *state, uint64_t pc) {
    /*if (cbExecTLEPCs.find(pc) != cbExecTLEPCs.end()) {
        killIllegalState(state, "Previous TLE", FKP_KILL_PREV_CONC_EXEC_TLE);
    } else*/
    if (inited) {
        /* concreteExecTimeout == 0 -> no timeout machanism
         * concreteExecTimeout == 1 -> measure mode
         * */
        if (lastForkTime > 0 && lastForkTimeState != -1 && concreteExecTimeout > 1) {
            if (time(0) - lastForkTime > concreteExecTimeout / 1000) {
                lastForkTime = time(nullptr);
                if (lastForkTimeState != state->getID()) {
                    lastForkTimeState = state->getID();
                } else {
                    cbExecTLEPCs.insert(pc);
                    killIllegalState(state, "Concrete exec TLE", FKP_KILL_TLE_CONC_EXEC);
//                localScopeKilledPathCount++;
//                updateSolverTimeout(state);
                }
            }
        } else if (Range::search(goodPcRanges, pc) && !Range::search(badPcRanges, pc)) {
            getDebugStream(state) << "onExecuteBlockStart. pc = " << hexval(pc) << " good\n";
        } else if (verboseBlockExecutionLog && Range::search(badPcRanges, pc) && !Range::search(badPcRanges, pc)) {
            getDebugStream(state) << "onExecuteBlockStart. pc = " << hexval(pc) << " bad\n";
        } else if (verboseBlockExecutionLog) {
            getDebugStream(state) << "onExecuteBlockStart. pc = " << hexval(pc) << " outside\n";
        }
    } else if (verboseBlockExecutionLog) {
        if (Range::search(goodPcRanges, pc) && !Range::search(badPcRanges, pc)) {
            getDebugStream(state) << "onExecuteBlockStart. pc = " << hexval(pc) << " good\n";
        } else if (Range::search(badPcRanges, pc) && !Range::search(badPcRanges, pc)) {
            getDebugStream(state) << "onExecuteBlockStart. pc = " << hexval(pc) << " bad\n";
        } else {
            getDebugStream(state) << "onExecuteBlockStart. pc = " << hexval(pc) << " outside\n";
        }
    }
}

void Propagator::NO_USE_GET_STACK_BOTTOM_USING_BP(S2EExecutionState *state) {
    // find the bottom bp
//    auto bp = state->regs()->getBp();
//    uint64_t nextBp;
//    state->mem()->read(bp, &nextBp, 8);
//    while (nextBp != 0) {
//        getDebugStream(state) << "bp=" << hexval(bp) << ", nextbp=" << hexval(nextBp) << "\n";
//        bp = nextBp;
//        state->mem()->read(bp, &nextBp, 8);
//    }
//    stack_base = bp;
//    getDebugStream(state) << " bottom of the stack is " << hexval(stack_base) << "\n";
}

void
Propagator::onBeforeSymbolicAddress(S2EExecutionState *state, klee::ref<klee::Expr> castedAddress, bool &doConcretize,
                                    CorePlugin::symbolicAddressReason) {
    if (unconditionalFork) {
        // only useful when unconditional fork is enabled bc we need to correct concolic first.
        if (symbolicPointerForkPoints.find(state->regs()->getPc()) != symbolicPointerForkPoints.end()) {
            // check constraints and correct concolics, if not possible then kill.
            if (!checkStateFeasibleAndRecomputeConcolics(state)) {
                killIllegalState(state, "Infeasible path constraints", FKP_KILL_INFEASIBLE_PATH);
                return;
            }
        }
    } else {
        // test if we are in the concrete mode
        auto pc = state->regs()->getPc();
        if (!isPcAllowed(state, pc)) {
            doConcretize = true;
            return;
        }

        // Ask the model to check if we need to fork
        std::set<klee::ArrayPtr> symbols;
        s2e()->getExecutor()->getArraysFromCond(castedAddress, symbols);
        const auto &spForkingSyms = model->symbolicPointerForkingSymbolNames;
        doConcretize = true;
        std::string forkingSymName;
        for (const auto &sym: symbols) {
            if (spForkingSyms.find(sym->getName()) != spForkingSyms.end()) {
                forkingSymName = sym->getName();
                doConcretize = false;
                break;
            }
        }

        if (!doConcretize) {
            getDebugStream(state) << "Allowed " << forkingSymName << " symbolic address forking at pc="
                                  << hexval(state->regs()->getPc()) << "\n";
            allowedSymbolicAddressPC[state->getID()] = state->regs()->getPc();
/*         add constraints for non-relavant symbols
*          Note: this may prevent to fork to some paths
 *          as sometimes the non-relavent symbols need to be changed to meet both the new
 *          constraint and the existing constraints.
 *          */
            for (const auto &sym: symbols) {
                if (spForkingSyms.find(sym->getName()) == spForkingSyms.end()) {
                    const auto &bindings = state->concolics->bindings;
                    const auto &binding = bindings.at(sym);
                    auto ul = klee::UpdateList::create(sym, 0);
                    auto cArraySize = binding.size();
                    auto concrete = binding;
                    assert(cArraySize > 0 && "arraysize == 0!");

                    for (unsigned long i = 0; i < cArraySize; i++) {
                        auto ce = klee::ConstantExpr::create(i, klee::Expr::Int32);
                        auto re = klee::ReadExpr::create(ul, ce);
                        auto eq = klee::EqExpr::create(re, klee::ConstantExpr::create(concrete[i], klee::Expr::Int8));
                        addConstraint(state, state->simplifyExpr(eq), "onBeforeSymbolicAddress limit other variables");
                    }
                }
            }
        }
    }
}


// Use whether the condition involves attacker/victim ip addr/port to determine whether to fork or no.
void Propagator::onSymbolicAddress(S2EExecutionState *state, klee::ref<klee::Expr> vAddr, uint64_t cAddr,
                                   bool &shouldConcretize, CorePlugin::symbolicAddressReason reason) {
    if (!shouldConcretize) {
        getDebugStream(state) << "allowed symbolic pointer forking @ " << hexval(state->regs()->getPc())
                              << ", addr="
                              << hexval(cAddr) << "\n";
    } else {
        // output FKG
        /* Note: this should be alredy handled at onStateDidntFork(). */
//        if (printConcretizationFKG) {
//            printFKGForAddedConstraint(state, klee::EqExpr::create(vAddr, klee::ConstantExpr::create(cAddr,
//                                                                                                     vAddr->getWidth())));
//        }
        if (encounteredSPConcretization.find(state->regs()->getPc()) == encounteredSPConcretization.end()) {
            encounteredSPConcretization.insert(state->regs()->getPc());
            getDebugStream(state) << "concretized symbolic pointer forking @ " << hexval(state->regs()->getPc())
                                  << ", addr=" << hexval(cAddr) << ", cond=\n" << dumpSingleQueryString(state,
                                                                                                        klee::EqExpr::create(
                                                                                                                vAddr,
                                                                                                                klee::ConstantExpr::create(
                                                                                                                        cAddr,
                                                                                                                        vAddr->getWidth())));
        } else {
            getDebugStream(state) << "concretized symbolic pointer forking @ " << hexval(state->regs()->getPc())
                                  << ", addr=" << hexval(cAddr) << "\n";
        }
    }
}

void Propagator::onTestPc(S2EExecutionState *state, uint64_t pc) {
    std::stringstream ss;
    ss << "on test pc " << hexval(pc) << ", owner " << (uint) pathOwner[state->getID()] << ", reg[";
    for (const auto &regOff: testPCAndRegs[pc]) {
        ss << regOff << "]=" << state->regs()->read(CPU_OFFSET(regs[regOff]), klee::Expr::Int64);
    }
//    getDebugStream(state) << "concretized r8d(wrong)=" << hexval(concretizedr8d) << "\n";
//    killIllegalState(state, "pc==0xffffffff8161c3b5");
}

void Propagator::onStateForkDecide(S2EExecutionState *oldState, bool *doFork) {

    // Check if it's out-of-range
    // If it's out-of-range, the pc is unlikely collide with the prev recorded trace as we don't record if we don't fork
    auto pc = oldState->regs()->getPc();
//    if (keepConcrete.find(oldState->getID()) != keepConcrete.end() && keepConcrete.at(oldState->getID())) {
//        *doFork = false;
//        return;
//    }

//    // The following is no longer useful as we switched to concrete execution when translating the block
//    if (!Range::search(goodPcRanges, pc)) {
////        getWarningsStream(oldState) << "fork disabled due to not in good pc ranges. pc = " << hexval(pc) << "\n";
//        *doFork = false;
//        return;
//    }
//
//    if (Range::search(badPcRanges, pc)) {
////        getWarningsStream(oldState) << "fork disabled due to in bad pc ranges. pc = " << hexval(pc) << "\n";
//        *doFork = false;
//        return;
//    }

    if (!isPcAllowed(oldState, pc)) {
        *doFork = false;
        return;
    }

    // Check if there's loop
    if (loopDetectionRange > 0) {
        auto fkpoints = forkPoints[oldState->getID()];
        // we assume the max # of forks in a loop is 10 and we allow at most 2 loops
        bool eq = false;
        auto lpsize = 1;
        for (; lpsize <= loopDetectionRange; lpsize++) {
            auto fkpsize = fkpoints.size();
            // [fkpsize](to be inserted) [fkpsize-lpsize] [fkpsize-lpsize*2]
            if (fkpsize - lpsize * loopDetectionTimes >= 0) {
                eq = true;
                for (auto i = 1; i <= loopDetectionTimes; i++) {
                    if (pc != fkpoints[fkpsize - lpsize * i]) {
                        eq = false;
                        break;
                    }
                }
                if (eq) {
                    // We've already found loop, no need to further detect and we need to keep eq to true
                    break;
                }
            } else {
                // otherwise we don't have enough fork points, skip
                break;
            }
        }
        if (eq) {
            getDebugStream(oldState) << "Loop detected: forking pc=" << hexval(pc) << ", loop size=" << lpsize << "\n";
//        auto i = 0;
//        for (auto fkp: forkPoints[oldState->getID()]) {
//            getDebugStream(oldState) << "[FK2],id=" << i++ << "," << hexval(fkp) << "\n";
//        }
            *doFork = false;
            // Should kill the state because otherwise it may take long time to fork->prevent fork->loop to exit loop? The normal states that exited loop shouldn't contain repeated forking points.
            killIllegalState(oldState, "Loop detected.", FKP_KILL_LOOP);
//        keepConcrete[oldState->getID()] = true;
        } else {
            // Do nothing. There may be other handlers that made the decision before us. We won't override their operation.
        }
    }
}

// Make the different owner equally splited into parent and child
void Propagator::onStateSplit(klee::StateSet &parent, klee::StateSet &child) {
    if (!unconditionalFork) {
        std::unordered_map<uint8_t, klee::StateSet> ownerStates;
        // use 3 for other
        for (const auto &ptrState: parent) {
            auto ptrS2EState = static_cast<S2EExecutionState *>(ptrState);
            if (pathOwner.find(ptrS2EState->getID()) != pathOwner.end()) {
                ownerStates[pathOwner[ptrS2EState->getID()]].insert(ptrState);
            } else {
                ownerStates[3].insert(ptrState);
            }
        }
        for (const auto &ptrState: child) {
            auto ptrS2EState = static_cast<S2EExecutionState *>(ptrState);
            if (pathOwner.find(ptrS2EState->getID()) != pathOwner.end()) {
                ownerStates[pathOwner[ptrS2EState->getID()]].insert(ptrState);
            } else {
                ownerStates[3].insert(ptrState);
            }
        }
        assert(ownerStates.size() <= 3 && ownerStates.size() >= 1);
        // dispense the states back to parent and child
        uint64_t subSetSize = parent.size() > child.size() ? parent.size() : child.size();
        parent.clear();
        child.clear();
        // split
        for (const auto &pOwnerSet: ownerStates) {
            for (const auto &ptrState: pOwnerSet.second) {
                if (pOwnerSet.first == 1 && parent.size() < subSetSize) {
                    parent.insert(ptrState);
                } else if (child.size() < subSetSize) {
                    child.insert(ptrState);
                } else {
                    (parent.size() > child.size() ? child : parent).insert(ptrState);
                }
            }
        }
    }
}

void Propagator::onProcessForkDecide(bool *proceed) {
    if (!unconditionalFork) {
        static uint64_t ownerStateCount[2];
        static bool ownerStateCountValid = false;
        bool foundOwner = false;
        for (const auto &pStateIDOwner: pathOwner) {
            if (pStateIDOwner.second == weakOwner) {
                *proceed = true;
                foundOwner = true;
                break;
            }
        }
        if (!foundOwner) {
            if (!ownerStateCountValid) {
                ownerStateCount[weakOwner] = finishedStatesCountByOwner[weakOwner];
                *proceed = false;
                ownerStateCountValid = true;
            } else {
                if (ownerStateCount[weakOwner] == finishedStatesCountByOwner[weakOwner]) {
                    ownerStateCountValid = false;
                    *proceed = true;
                } else {
                    ownerStateCount[weakOwner] = finishedStatesCountByOwner[weakOwner];
                    *proceed = false;
                }
            }
        }
    }
}

bool Propagator::checkStateFeasibleAndRecomputeConcolics(S2EExecutionState *state) {
    if (!solver) {
        solver = klee::Z3Solver::createResetSolver();
    }
    klee::Solver::Validity result;
    if (solver->evaluate(klee::Query(state->constraints(), klee::ConstantExpr::alloc(1, klee::Expr::Bool)), result)) {
        if (result == klee::Solver::True) {
            // TODO: Try remove solving new concolics. But consider it may cause imprecision of the concrete holes.
            state->solve(state->constraints(), *(state->concolics));

            //         std::stringstream ss;
            //         ss << "[checkStateFeasibleAndRecomputeConcolics]1. New concolic assignments:\n";
            //                for (const auto& binding:state->concolics->bindings) {
            //     ss << binding.first->getName() << "=";
            //     for (const auto& b : binding.second) {
            //            ss << hexval(b) << " ";
            //        }
            //    }
            //    ss << "\n";
            //        getDebugStream(state) << ss.str() << "\n";

            return true;
        }
    } else {
        getDebugStream(state) << "Evaluate current state constraints failed\n";
    }
    return false;
}

void Propagator::onTimeout(S2EExecutionState *state, CorePlugin::TimeoutReason r) {
//    m_monitor->hookAddress(state->regs()->getPc(), sigc::mem_fun(*this, &Propagator::onPreviousTLEPC));
    if (r == CorePlugin::TimeoutReason::SOLVER) {
        auto pc = state->regs()->getPc();
//        badPcRanges.emplace_back(pc, pc, 0);
        getDebugStream(state) << hexval(pc) << ":Solver TLE, killed.\n";
        // Update timeout counts
        if (pathOwner[state->getID()] == model->victimOwner || pathOwner[state->getID()] == model->attackerOwner) {
            s2e()->fetchAndIncreaseStatesCount(pathOwner[state->getID()], weakOwner, finishedStatesCountByOwner,
                                               &timeoutStateCounts, true);
//            localScopeKilledPathCount++;
//            updateSolverTimeout(state);
        }
        killIllegalState(state, "Solver TLE", FKP_KILL_TLE_SOLVER);
    } else if (r == CorePlugin::TimeoutReason::TB_EXEC) {
        killIllegalState(state, "Block execution TLE", FKP_KILL_TLE_EXEC);
    }
}

void Propagator::terminateState(S2EExecutionState *state, uint64_t pc) {
    s2e()->getExecutor()->terminateState(*state, "reached termination point.");
}

void Propagator::onPreviousTLEPC(S2EExecutionState *state, uint64_t pc) {
    killIllegalState(state, "Previous TLE", FKP_KILL_PREV_CONC_EXEC_TLE);
}

//void Propagator::onNonForkingConstraintAdded(S2EExecutionState *state, const klee::ref<klee::Expr> &constraint) {
//    if (printConcretizationFKG) {
//        printFKGForAddedConstraint(state, constraint);
//    }
//}

void Propagator::onException(S2EExecutionState *state, unsigned int index, uint64_t pc) {
    getDebugStream(state) << "onException: pc=" << hexval(pc) << ", int=" << index << "\n";
    pcAtInterrupt[state->getID()] = pc;
    if (platModel->killOnException(state, index, pc)) {
        killIllegalState(state, "kernel panic (onException), kill state", FKP_KILL_PANIC);
    }
}

bool
Propagator::readRegister64(S2EExecutionState *state, unsigned int regOff, uint64_t *val, const std::string &reason) {
    auto pc = state->regs()->getPc();
    auto isCon = state->regs()->read(CPU_OFFSET(regs[regOff]), val, 8, false);    // 8 bytes
    if (!isCon) {
        auto sym = state->regs()->read(CPU_OFFSET(regs[regOff]), klee::Expr::Int64);
        if (state->regs()->read(CPU_OFFSET(regs[regOff]), val, 8, true)) {
            getDebugStream(state) << "concretizing register " << regOff << " to " << s2e::hexval(*val) << ", pc="
                                  << s2e::hexval(pc) << ", reason: " << reason << "\n";
            addConstraint(state, klee::EqExpr::create(sym, klee::ConstantExpr::create(*val, klee::Expr::Int64)),
                          "concretizing register: " + reason);
        } else {
            getDebugStream(state) << "Failed to concretize register " << regOff << ", pc=" << s2e::hexval(pc)
                                  << ", reason: " << reason << ", reg" << "=\n"
                                  << state->regs()->read(CPU_OFFSET(regs[regOff]), klee::Expr::Int64) << "\n";
            return false;
        }
    }
    return true;
}

//bool Propagator::readCR3(S2EExecutionState *state, uint64_t *val, const std::string &reason) {
//    auto pc = state->regs()->getPc();
//    auto cr3 = state->regs()->read(CPU_OFFSET(cr[3]), 8*8);    // 8 bytes
//
//    if (!isCon) {
//        auto sym = state->regs()->read(CPU_OFFSET(cr[3]), klee::Expr::Int64);
//        if (state->regs()->read((CPU_OFFSET(cr[3]), val, 8, true)) {
//            getDebugStream(state) << "concretizing register cr3 to " << s2e::hexval(*val) << ", pc=" << s2e::hexval(pc)
//                                  << ", reason: " << reason << "\n";
//            addConstraint(state, klee::EqExpr::create(sym, klee::ConstantExpr::create(*val, klee::Expr::Int64)),
//                          "concretizing register cr3: " + reason);
//        } else {
//            getDebugStream(state) << "Failed to concretize register cr3, pc=" << s2e::hexval(pc) << ", reason: "
//                                  << reason << ", reg" << "=\n"
//                                  << state->regs()->read(CPU_OFFSET(cr[3]), klee::Expr::Int64) << "\n";
//            return false;
//        }
//    }
//    return true;
//}

void Propagator::updateSolverTimeout(S2EExecutionState *state) {
    auto finishedCount = finishedStatesCountByOwner[0] + finishedStatesCountByOwner[1];
    if (localFinishedPathCount > 0 && finishedCount > 0) {
        auto percent = localScopeKilledPathCount * 100.0 / (localFinishedPathCount + localScopeKilledPathCount);
        auto new_timeout = std::max((int64_t) currentTimeout -
                                    (int64_t) (solverTimeoutPidController->calculate(timeoutStatePercentage, percent) *
                                               feedBackScale), (int64_t) minSolverTimeout);
        getDebugStream(state) << "Current " << (uint) percent << "% local TLE(" << localScopeKilledPathCount << "/"
                              << (localFinishedPathCount + localScopeKilledPathCount) << "), desired "
                              << timeoutStatePercentage << "%, " << (uint) (timeoutStateCounts * 100.0 / finishedCount)
                              << "% global TLE(" << timeoutStateCounts << "/" << finishedCount << "), Z3 timeout "
                              << currentTimeout << " -> " << new_timeout << "\n";
        if (new_timeout != currentTimeout) {
            currentTimeout = new_timeout;
            klee::SolverManager::solver()->setTimeout(currentTimeout);
            concreteExecTimeout = new_timeout;
        }
    }
}

bool Propagator::isPcAllowed(S2EExecutionState *state, uint64_t pc) {
    if (!Range::search(goodPcRanges, pc) || Range::search(badPcRanges, pc)) {
        return false;
    } else {
        return platModel->isPcAllowed(state, pc);
    }
}


// TODO: Seems like the concolis used to compute hash is different when we used for symbolic pointer forking
