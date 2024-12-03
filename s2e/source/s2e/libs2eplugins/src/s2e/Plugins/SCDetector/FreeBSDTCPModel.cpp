#include "FreeBSDTCPModel.h"

FreeBSDTCPModel::FreeBSDTCPModel(s2e::plugins::Propagator *scd) : ProtocolModel(scd) {
    entryPoints.insert(0xffffffff80d4645c);
    outputPoints.insert(0xffffffff80d387ad);
    terminatePoints.insert(0xffffffff80d470fe);
    terminatePoints.insert(0xffffffff80d470ed);
    terminatePoints.insert(0xffffffff80d4706a);
    terminatePoints.insert(0xffffffff80d46ec0);

    attackerIPLastB = 16;
    victimIPLastB = 1;
    tcpHdrSize = 20; //32; //20; // now with option
    atkrSport = htobe16(9638);
    atkrNewSport = htobe16(1996);
    vctmSport = htobe16(8369);
    vctmNewSport = htobe16(6991);
    srvPort = htobe16(12345);
    closedPort = htobe16(54321);
    attackerOwner = 1;
    victimOwner = 2;
    defaultOwner = attackerOwner | victimOwner;
}

void FreeBSDTCPModel::onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) {
    g_s2e->getDebugStream(state) << "ENTERING tcp_input_with_port.\n";
    // Symbolize header
    uint64_t tcpHdrPtr;
    if (!scd->readRegister64(state, R_EBX, &tcpHdrPtr, "onEntryFunction, this shouldn't fail.")) {
        g_s2e->getDebugStream(state) << "Fatal: cannot get rbx at onEntryFunction.\n";
        exit(-1);
    }
    uint64_t ipAddrLastBPtr;
    if (!scd->readRegister64(state, 15, &ipAddrLastBPtr, "onEntryFunction, this shouldn't fail.")) {
        g_s2e->getDebugStream(state) << "Fatal: cannot get r15 at onEntryFunction.\n";
        exit(-1);
    }
    ipAddrLastBPtr += 0xf;

    std::string ipOwnerSymbolName;
    std::vector<klee::ref<klee::Expr>> sport_symbol;
    std::string sportSymbolName;
    std::vector<klee::ref<klee::Expr>> dport_symbol;
    std::string dportSymbolName;

    scd->makeSymbolic(state, tcpHdrPtr + 0, 2, "pkt_sport", &sport_symbol, &sportSymbolName);
    scd->makeSymbolic(state, tcpHdrPtr + 2, 2, "pkt_dport", &dport_symbol, &dportSymbolName);
    scd->makeSymbolic(state, tcpHdrPtr + 4, 4, "pkt_seq");
    scd->makeSymbolic(state, tcpHdrPtr + 8, 4, "pkt_ack");
    if (tcpHdrSize > 20) {
        scd->makeSymbolic(state, tcpHdrPtr + 12, 1, "4_bit_doff");
    }
    scd->makeSymbolic(state, tcpHdrPtr + 13, 1, "flags");
    scd->makeSymbolic(state, tcpHdrPtr + 14, 2, "win_size");
    // Ignore checksum with 16-17
    scd->makeSymbolic(state, tcpHdrPtr + 18, 2, "urg_ptr");
    // TCP Options
    if (tcpHdrSize > 20) {
        // symbolize options, this requires a tcp header having 32 bytes=20 header + 10 option + 2 padding
        // option length includes size and type
//        scd->makeSymbolic(state, tcpHdrPtr + 20, 1, "tcp_opt_kind", &opt_kind_symbol);
//        scd->makeSymbolic(state, tcpHdrPtr + 20 + 1, 1, "tcp_opt_len", &opt_len_symbol);
//        scd->makeSymbolic(state, tcpHdrPtr + 20 + 2, tcpHdrSize - 22, "tcp_opt_payload",
//                          &opt_data_symbol);
    }

    // Symbolic src ip
    scd->makeSymbolic(state, ipAddrLastBPtr, 1, "ipAddrLastB", &saddr_last_byte_symbol, &ipOwnerSymbolName);

    // allow symbolic pointer forking to distingusih the owner
    symbolicPointerForkingSymbolNames.insert(sportSymbolName);
    symbolicPointerForkingSymbolNames.insert(dportSymbolName);
    symbolicPointerForkingSymbolNames.insert(ipOwnerSymbolName);

    // construct constraints
    auto ip_victim_eq = klee::EqExpr::create(saddr_last_byte_symbol[0],
                                             klee::ConstantExpr::create(victimIPLastB, klee::Expr::Int8));
    auto ip_attacker_eq = klee::EqExpr::create(saddr_last_byte_symbol[0],
                                               klee::ConstantExpr::create(attackerIPLastB, klee::Expr::Int8));
    // network use big endian
    auto atkrSrcPort_eq_0 = klee::EqExpr::create(sport_symbol[0],
                                                 klee::ConstantExpr::create(*((uint8_t *) &atkrSport),
                                                                            klee::Expr::Int8));
    auto atkrSrcPort_eq_1 = klee::EqExpr::create(sport_symbol[1],
                                                 klee::ConstantExpr::create(*(((uint8_t *) &atkrSport) + 1),
                                                                            klee::Expr::Int8));
    auto atkrNewSrcPort_eq_0 = klee::EqExpr::create(sport_symbol[0],
                                                    klee::ConstantExpr::create(*((uint8_t *) &atkrNewSport),
                                                                               klee::Expr::Int8));
    auto atkrNewSrcPort_eq_1 = klee::EqExpr::create(sport_symbol[1],
                                                    klee::ConstantExpr::create(*(((uint8_t *) &atkrNewSport) + 1),
                                                                               klee::Expr::Int8));
    auto vctmSrcPort_eq_0 = klee::EqExpr::create(sport_symbol[0],
                                                 klee::ConstantExpr::create(*((uint8_t *) &vctmSport),
                                                                            klee::Expr::Int8));
    auto vctmSrcPort_eq_1 = klee::EqExpr::create(sport_symbol[1],
                                                 klee::ConstantExpr::create(*(((uint8_t *) &vctmSport) + 1),
                                                                            klee::Expr::Int8));
    auto vctmNewSrcPort_eq_0 = klee::EqExpr::create(sport_symbol[0],
                                                    klee::ConstantExpr::create(*((uint8_t *) &vctmNewSport),
                                                                               klee::Expr::Int8));
    auto vctmNewSrcPort_eq_1 = klee::EqExpr::create(sport_symbol[1],
                                                    klee::ConstantExpr::create(*(((uint8_t *) &vctmNewSport) + 1),
                                                                               klee::Expr::Int8));
    auto serverDstPort_eq_0 = klee::EqExpr::create(dport_symbol[0],
                                                   klee::ConstantExpr::create(*((uint8_t *) &srvPort),
                                                                              klee::Expr::Int8));
    auto serverDstPort_eq_1 = klee::EqExpr::create(dport_symbol[1],
                                                   klee::ConstantExpr::create(*(((uint8_t *) &srvPort) + 1),
                                                                              klee::Expr::Int8));

    auto closedDstPort_eq_0 = klee::EqExpr::create(dport_symbol[0],
                                                   klee::ConstantExpr::create(*((uint8_t *) &closedPort),
                                                                              klee::Expr::Int8));
    auto closedDstPort_eq_1 = klee::EqExpr::create(dport_symbol[1],
                                                   klee::ConstantExpr::create(*(((uint8_t *) &closedPort) + 1),
                                                                              klee::Expr::Int8));


    auto dstPortConstraints = klee::OrExpr::create(klee::AndExpr::create(serverDstPort_eq_0, serverDstPort_eq_1),
                                                   klee::AndExpr::create(closedDstPort_eq_0, closedDstPort_eq_1));
    auto attacker_constraints = klee::AndExpr::create(ip_attacker_eq, klee::AndExpr::create(dstPortConstraints,
                                                                                            klee::OrExpr::create(
                                                                                                    klee::AndExpr::create(
                                                                                                            atkrSrcPort_eq_0,
                                                                                                            atkrSrcPort_eq_1),
                                                                                                    klee::AndExpr::create(
                                                                                                            atkrNewSrcPort_eq_0,
                                                                                                            atkrNewSrcPort_eq_1))));
    auto victim_constraints = klee::AndExpr::create(ip_victim_eq, klee::AndExpr::create(dstPortConstraints,
                                                                                        klee::OrExpr::create(
                                                                                                klee::AndExpr::create(
                                                                                                        vctmSrcPort_eq_0,
                                                                                                        vctmSrcPort_eq_1),
                                                                                                klee::AndExpr::create(
                                                                                                        vctmNewSrcPort_eq_0,
                                                                                                        vctmNewSrcPort_eq_1))));

    // add constraints
    assert(scd->addConstraint(state, klee::OrExpr::create(attacker_constraints, victim_constraints),
                              "input constraints") && "add initial constraints failed.\n");

    // add option constraints
    if (tcpHdrSize > 20) {
        // length include type and len field (2 bytes)
//        std::unordered_map<uint8_t, uint8_t> supportedOpts = {{0, 0},
//                                                              {1, 0},
//                                                              {2, 4},
//                                                              {3, 3},
//                                                              {4, 2},
//                                                              {5, 10},
//                                                              {8, 10}};
//        klee::ref<klee::Expr> optConstaints = klee::ConstantExpr::create(0, klee::Expr::Int8);
//        assert(!supportedOpts.empty());
//        for (const auto &pKindLen: supportedOpts) {
//            if (!isa<klee::ConstantExpr>(optConstaints)) {
//                optConstaints = klee::OrExpr::create(optConstaints,
//                                                     buildOptConstraint(pKindLen.first, pKindLen.second));
//            } else {
//                optConstaints = buildOptConstraint(pKindLen.first, pKindLen.second);
//            }
//        }
//        assert(scd->addConstraint(state, optConstaints, "option constraints") && "add option constraints failed.\n");
    }

    g_s2e->getDebugStream(state) << "TCP packet header symbolized. Current concolics is=\n"
                                 << state->concolics->evaluate(scd->extendedRead(state, tcpHdrPtr, tcpHdrSize * 8))
                                 << "\n";

    // Avoid symbolizing other field in the buffer, mbuffer already includes the range of mbuffer->m_data
    uint64_t mBuffPtr;
    if (scd->readRegister64(state, 13, &mBuffPtr, "onEntryFunction, get mbuffer.")) {
        scd->disallowedGWRanges.emplace_back(mBuffPtr, mBuffPtr + 256 - 1, 0);
        g_s2e->getDebugStream(state) << "Input address range 0: " << s2e::hexval(mBuffPtr) << " - "
                                     << s2e::hexval(mBuffPtr + 256 - 1) << "\n";

//        bool err = false;
//        auto dataPtr = scd->readAndConcretizeMemory64(state, mBuffPtr + 0x10, err, "get mbuf->m_data");
//        if (!err) {
//            auto dataLen = scd->readAndConcretizeMemory32(state, mBuffPtr + 0x18, err, "get mbuf->m_len");
//            if (!err) {
//                scd->disallowedGWRanges.emplace_back(dataPtr, dataPtr + dataLen - 1, 0);
//                g_s2e->getDebugStream(state) << "Input address range 1: " << s2e::hexval(dataPtr) << " - "
//                                             << s2e::hexval(dataPtr + dataLen - 1) << "\n";
//            } else {
//                g_s2e->getDebugStream(state) << "Error: cannot get mbuf->m_len.\n";
//            }
//        } else {
//            g_s2e->getDebugStream(state) << "Error: cannot get mbuf->m_data.\n";
//        }
    } else {
        g_s2e->getDebugStream(state) << "onEntryFunction, cannot get r13 for mbuffer.\n";
    }

    state->regs()->write(CPU_OFFSET(timer_interrupt_disabled), 1);
    state->regs()->write(CPU_OFFSET(all_apic_interrupts_disabled), 1);

    // Add state-related constraints
    std::string victimStateSymName;
    std::vector<klee::ref<klee::Expr>> victimStateSym;
    scd->makeSymbolic(state, 0xfffff8000a00f266, 1, "victim_state", &victimStateSym, &victimStateSymName);
    scd->addConstraint(state, klee::NotExpr::create(klee::EqExpr::create(
            klee::AndExpr::create(victimStateSym[0], klee::ConstantExpr::create(0xf, klee::Expr::Int8)),
            klee::ConstantExpr::create(0x1, klee::Expr::Int8))), "victim state constraint");
    std::string attackerStateSymName;
    std::vector<klee::ref<klee::Expr>> attackerStateSym;
    scd->makeSymbolic(state, 0xfffff80006352266, 1, "attacker_state", &attackerStateSym, &attackerStateSymName);
    scd->addConstraint(state, klee::NotExpr::create(klee::EqExpr::create(
            klee::AndExpr::create(attackerStateSym[0], klee::ConstantExpr::create(0xf, klee::Expr::Int8)),
            klee::ConstantExpr::create(0x1, klee::Expr::Int8))), "attacker state constraint");
    std::string listenStateSymName;
    std::vector<klee::ref<klee::Expr>> listenStateSym;
    scd->makeSymbolic(state, 0xfffff800063527a6, 1, "listen_state", &listenStateSym, &listenStateSymName);
    scd->addConstraint(state, klee::EqExpr::create(
            klee::AndExpr::create(listenStateSym[0], klee::ConstantExpr::create(0xf, klee::Expr::Int8)),
            klee::ConstantExpr::create(0x1, klee::Expr::Int8)), "listen state constraint");

    // Sort disallowed GW
    if (!s2e::plugins::Propagator::Range::sortRanges(scd->disallowedGWRanges)) {
        g_s2e->getWarningsStream() << "disallowedGWRanges contains overlap!\n";
        exit(-1);
    }
}

s2e::plugins::GlobalWrite2 FreeBSDTCPModel::onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) {
    uint64_t tcpHdrPtr;
    if (!scd->readRegister64(state, R_ESI, &tcpHdrPtr, "onOutputFunction, read rsi.")) {
        g_s2e->getDebugStream(state) << "Error: cannot get rsi at onOutputFunction.\n";
        return {};
    }
    tcpHdrPtr += 0x14;

    // Write check to 0
    uint16_t _zero = 0;
    if (!state->mem()->write(tcpHdrPtr + 16, _zero)) {
        g_s2e->getDebugStream(state) << "Failed to write 0 to check sum in output function, pc=" << s2e::hexval(pc)
                                     << "\n";
    }

    // Read doff
    bool err = false;
    auto doff = scd->readAndConcretizeMemory8(state, tcpHdrPtr + 12, err, "Read data off in TCP output");
    doff >>= 4; // The remaining 12 bits are flags
    if (err) {
        g_s2e->getDebugStream(state) << "Failed to access *(th->doff) on output function pc=" << s2e::hexval(pc)
                                     << ", th->doff=\n" << s2e::hexval(tcpHdrPtr + 12) << "\n";
        return {};
    } else {
        g_s2e->getDebugStream(state) << "doff=" << (unsigned) doff << "\n";
    }

    auto sizeToRead = doff * 4 >= tcpHdrSize ? tcpHdrSize : doff * 4;
    g_s2e->getDebugStream(state) << "read " << sizeToRead << " bytes on output\n";
    auto tcpHdr = s2e::plugins::Propagator::extendedRead(state, tcpHdrPtr, sizeToRead * 8); // 160 bits
    if (tcpHdr.isNull()) { // 8 bytes
        g_s2e->getDebugStream(state) << "Failed to access tcp header on output function pc=" << s2e::hexval(pc)
                                     << ", tcp header=\n" << s2e::hexval(tcpHdrPtr) << "\n";
        return {};
    }

    // Padding with option 1 to normalize the output length. This is required as all symbols should have equal length
    if (sizeToRead < tcpHdrSize) {
        for (auto i = 0; i < tcpHdrSize - sizeToRead; i++) {
            tcpHdr = klee::ConcatExpr::create(tcpHdr, klee::ConstantExpr::create(1, klee::Expr::Int8));
        }
    }
    // Now tcpHdr must be length of tcpHdrSize
    // Evaluate the concrete output
    g_s2e->getDebugStream(state) << "Concrete output: " << state->concolics->evaluate(tcpHdr) << "\n";

    auto tmp = s2e::plugins::GlobalWrite2();
    tmp.size = tcpHdrSize;
    tmp.isOutput = true;
    tmp.pc = pc;
    tmp.summary = tcpHdr;
    tmp.cAddr = tcpHdrPtr;
    tmp.stateID = state->getID();
    tmp.isPcPrecise = true;

    return tmp;
}

uint8_t FreeBSDTCPModel::getNewStateOwner(s2e::S2EExecutionState *oldState, s2e::S2EExecutionState *newState,
                                          const std::vector<klee::ref<klee::Expr>> &newCond,
                                          s2e::plugins::Propagator *scd, uint8_t oldOwner) {
    if (oldOwner == victimOwner || oldOwner == attackerOwner) {
        // Shortcut, as it's unlikely the owner constraint will be losen
        return oldOwner;
    }
    uint8_t newOwner = victimOwner | attackerOwner;
    auto solver = klee::SolverManager::solver(*newState)->solver;
    {
        klee::Query query(newState->constraints(), klee::EqExpr::create(saddr_last_byte_symbol[0],
                                                                        klee::ConstantExpr::create(victimIPLastB,
                                                                                                   klee::Expr::Int8)));
        bool mustBeFalse;
        if (solver->mustBeFalse(query, mustBeFalse)) {
            if (mustBeFalse) {
                newOwner &= ~victimOwner;
            }
        } else {
            g_s2e->getDebugStream(newState) << "Owner solving timeout.\n";
            return 0;
        }
    }
    {
        klee::Query query(newState->constraints(), klee::EqExpr::create(saddr_last_byte_symbol[0],
                                                                        klee::ConstantExpr::create(attackerIPLastB,
                                                                                                   klee::Expr::Int8)));
        bool mustBeFalse;
        if (solver->mustBeFalse(query, mustBeFalse)) {
            if (mustBeFalse) {
                newOwner &= ~attackerOwner;
            }
        } else {
            g_s2e->getDebugStream(newState) << "Owner solving timeout.\n";
            return 0;
        }
    }

    // If no symbol was found, return newOwner=3
    if (newOwner != oldOwner) {
        g_s2e->getDebugStream(newState) << "Owner changed from " << (uint) oldOwner << " to " << (uint) newOwner
                                        << "\n";
    }
    return newOwner;
}
