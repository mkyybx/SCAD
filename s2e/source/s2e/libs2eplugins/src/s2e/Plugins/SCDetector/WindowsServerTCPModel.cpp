#include "WindowsServerTCPModel.h"

WindowsServerTCPModel::WindowsServerTCPModel(s2e::plugins::Propagator *scd) : ProtocolModel(scd) {
    attackerIPLastB = 16;
    victimIPLastB = 1;
    tcpHdrSize = 20; //32; //20; // now with option
    atkrSport = htobe16(9638);
    atkrNewSport = htobe16(1996);
    vctmSport = htobe16(8369);
    vctmNewSport = htobe16(6991);
    srvPort = htobe16(12345);
    closedPort = htobe16(54321);

    attackerOwner = 0b01;
    victimOwner = 0b10;
    defaultOwner = attackerOwner | victimOwner;

    entryPoints.insert(0xfffff8036b781a70); // Start of TcpReceive
//    entryPoints.insert(0xfffff8036b782750); // Start of TcpMatchReceive
    terminatePoints.insert(0xfffff8036b7c91b4);
    terminatePoints.insert(0xfffff8036b7d89f0);
    terminatePoints.insert(0xfffff8036b88e83c);
    terminatePoints.insert(0xfffff8036b7c6740);
    terminatePoints.insert(0xfffff8036b78272e); // Ret of TcpReceive
//    outputPoints.insert(0xfffff8036b7783a7);    // This location can be used to get output summary at TcpTcbHeaderSend
    outputPoints.insert(0xfffff8036b7721f0);    // Start of TcpTcbSend
    outputPoints.insert(0xfffff8036b7781b0);    // Start of TcpTcbHeaderSend
    outputPoints.insert(0xfffff8036b775b10);    // Start of IpNlpFastSendDatagram
    outputPoints.insert(0xfffff8036b77b550);    // Start of IppSendDatagramsCommon
    outputPoints.insert(0xfffff8036b7da3e0);    // Start of IpNlpSenDatagrams
    outputPoints.insert(0xfffff8036b7da0cc);    // Start of TcpResetSend

}

void WindowsServerTCPModel::onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) {
//    scd->m_monitor->hookAddress(0xfffff8036b7826fb, sigc::mem_fun(*this, &WindowsServerTCPModel::symbolizingInput));
    symbolizingInput(state, pc);
}

void WindowsServerTCPModel::symbolizingInput(s2e::S2EExecutionState *state, uint64_t pc) {
    // Symbolize the input packet
    uint64_t tcpHdrPtr;
    uint64_t ipAddrLastBPtr;
    if (pc == 0xfffff8036b782750) {
        uint64_t rdx;
        if (!scd->readRegister64(state, R_EDX, &rdx, "onEntryFunction, this shouldn't fail.")) {
            g_s2e->getDebugStream(state) << "Fatal: cannot get rdx at onEntryFunction.\n";
            exit(-1);
        }
        // *(rdx+0x18)+0x08
        bool err;
        auto _01 = scd->readAndConcretizeMemory64(state, rdx + 0x18, err, "onEntry: *(rdx+0x18)");
        if (err) {
            g_s2e->getDebugStream(state) << "Fatal: cannot get *(rdx+0x18) at onEntryFunction.\n";
            exit(-1);
        }
        tcpHdrPtr = _01 + 0x08;
        ipAddrLastBPtr = _01 + 0x3;
    } else if (pc == 0xfffff8036b781a70) {
        tcpHdrPtr = 0xffffce8c95726696;
        ipAddrLastBPtr = tcpHdrPtr - 0x5;
        // sanity check
        bool err;
        auto dport = scd->readAndConcretizeMemory16(state, tcpHdrPtr + 2, err,
                                                    "Sanity check for dport, this shouldn't appear!");
        if (dport != 0x3039 && dport != 0x3930) {
            g_s2e->getDebugStream(state) << "Fatal: dport is not 12345 and it's " << dport
                                         << ". This means we should use TcpMatchReceive as a start or rerun the snapshot\n";
            abort();
        }
    } else {
        abort(); // impossible
    }

    // Symbolize the header
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
        scd->makeSymbolic(state, tcpHdrPtr + 20, 1, "tcp_opt_kind", &opt_kind_symbol);
        scd->makeSymbolic(state, tcpHdrPtr + 20 + 1, 1, "tcp_opt_len", &opt_len_symbol);
        scd->makeSymbolic(state, tcpHdrPtr + 20 + 2, tcpHdrSize - 22, "tcp_opt_payload",
                          &opt_data_symbol);
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
        std::unordered_map<uint8_t, uint8_t> supportedOpts = {{0, 0},
                                                              {1, 0},
                                                              {2, 4},
                                                              {3, 3},
                                                              {4, 2},
                                                              {5, 10},
                                                              {8, 10}};
        klee::ref<klee::Expr> optConstaints = klee::ConstantExpr::create(0, klee::Expr::Int8);
        assert(!supportedOpts.empty());
        for (const auto &pKindLen: supportedOpts) {
            if (!isa<klee::ConstantExpr>(optConstaints)) {
                optConstaints = klee::OrExpr::create(optConstaints,
                                                     buildOptConstraint(pKindLen.first, pKindLen.second));
            } else {
                optConstaints = buildOptConstraint(pKindLen.first, pKindLen.second);
            }
        }
        assert(scd->addConstraint(state, optConstaints, "option constraints") && "add option constraints failed.\n");
    }

    g_s2e->getDebugStream(state) << "TCP packet header symbolized. Current concolics is=\n"
                                 << state->concolics->evaluate(scd->extendedRead(state, tcpHdrPtr, tcpHdrSize * 8))
                                 << "\n";

    /* Block symbolizing other fields for buffer
     *    *(rdx+0x18)-0x1a---------*(rdx+0x18)-0x1a+0x40
     *    *(rdx+0x18)+0x08=tcpHdrPtr
     *    tcpHdrPtr-0x08-0x1a-------tcpHdrPtr-0x08-0x1a+0x40
     * */
    scd->disallowedGWRanges.emplace_back(tcpHdrPtr - 0x08 - 0x1a, tcpHdrPtr - 0x08 - 0x1a + 0x40, 0);
    g_s2e->getDebugStream(state) << "Input address range 0: " << s2e::hexval(tcpHdrPtr - 0x08 - 0x1a) << " - "
                                 << s2e::hexval(tcpHdrPtr - 0x08 - 0x1a + 0x40) << "\n";

    state->regs()->write(CPU_OFFSET(timer_interrupt_disabled), 1);
    state->regs()->write(CPU_OFFSET(all_apic_interrupts_disabled), 1);

    // TODO: sk state hook

    // Sort disallowed GW
    if (!s2e::plugins::Propagator::Range::sortRanges(scd->disallowedGWRanges)) {
        g_s2e->getWarningsStream() << "disallowedGWRanges contains overlap!\n";
        exit(-1);
    }
}

s2e::plugins::GlobalWrite2 WindowsServerTCPModel::onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) {
    if (pc == 0xfffff8036b7783a7) {
        // With summary
        // *(*(rax+0x08)+0x08)+*(uint8_t*)((*(rax+0x08)+0x10))+0x40
        uint64_t rax;
        if (!scd->readRegister64(state, R_EAX, &rax, "onOutputFunction, read rax.")) {
            g_s2e->getDebugStream(state) << "Error: cannot get rax at onOutputFunction.\n";
            return {};
        }
        bool err;
        auto _01 = scd->readAndConcretizeMemory64(state, rax + 0x8, err, "onOutputFunction: *(rax+0x8)");
        if (err) {
            g_s2e->getDebugStream(state) << "Error: cannot get *(rax+0x8) at onOutputFunction.\n";
            return {};
        }
        auto _02 = scd->readAndConcretizeMemory64(state, _01 + 0x8, err, "onOutputFunction: *(*(rax+0x08)+0x08)");
        if (err) {
            g_s2e->getDebugStream(state) << "Error: cannot get *(*(rax+0x08)+0x08) at onOutputFunction.\n";
            return {};
        }
        auto _12 = scd->readAndConcretizeMemory8(state, _01 + 0x10, err, "onOutputFunction: *(*(rax+0x08)+0x10)");
        if (err) {
            g_s2e->getDebugStream(state) << "Error: cannot get *(*(rax+0x08)+0x10) at onOutputFunction.\n";
            return {};
        }
        auto hdrPtr = _02 + _12 + 0x40;

        // Write check to 0
        uint16_t _zero = 0;
        if (!state->mem()->write(hdrPtr + 16, _zero)) {
            g_s2e->getDebugStream(state) << "Failed to write 0 to check sum in output function, pc=" << s2e::hexval(pc)
                                         << "\n";
        }

        // Read doff
        err = false;
        auto doff = scd->readAndConcretizeMemory8(state, hdrPtr + 12, err, "Read data off in TCP output");
        doff >>= 4; // The remaining 12 bits are flags
        if (err) {
            g_s2e->getDebugStream(state) << "Failed to access *(th->doff) on output function pc=" << s2e::hexval(pc)
                                         << ", th->doff=\n" << s2e::hexval(hdrPtr + 12) << "\n";
            return {};
        } else {
            g_s2e->getDebugStream(state) << "doff=" << (unsigned) doff << "\n";
        }

        auto sizeToRead = doff * 4 >= tcpHdrSize ? tcpHdrSize : doff * 4;
        g_s2e->getDebugStream(state) << "read " << sizeToRead << " bytes on output\n";
        auto tcpHdr = s2e::plugins::Propagator::extendedRead(state, hdrPtr, sizeToRead * 8); // 160 bits
        if (tcpHdr.isNull()) { // 8 bytes
            g_s2e->getDebugStream(state) << "Failed to access tcp header on output function pc=" << s2e::hexval(pc)
                                         << ", tcp header=\n" << s2e::hexval(hdrPtr) << "\n";
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
        tmp.cAddr = hdrPtr;
        tmp.stateID = state->getID();
        tmp.isPcPrecise = true;

        return tmp;
    } else {
        // Without summary
        auto tmp = s2e::plugins::GlobalWrite2();
        tmp.size = 1;
        tmp.isOutput = true;
        tmp.pc = pc;
        tmp.summary = klee::ConstantExpr::create(1, klee::Expr::Int8);
        tmp.cAddr = 0xdbeef;
        tmp.stateID = state->getID();
        tmp.isPcPrecise = true;

        return tmp;
    }
}


uint8_t WindowsServerTCPModel::getNewStateOwner(s2e::S2EExecutionState *oldState,
                                                s2e::S2EExecutionState *newState,
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

klee::ref<klee::Expr> WindowsServerTCPModel::buildOptConstraint(uint8_t kind, uint8_t len) {
    /* All ? : expression is used to deal with kind = 0 or 1 and len = 0*/
    // Kind
    auto curConstraint = klee::EqExpr::create(
            klee::ConstantExpr::create(kind, klee::Expr::Int8), opt_kind_symbol[0]);
    // Length
    curConstraint = klee::AndExpr::create(curConstraint, klee::EqExpr::create(
            klee::ConstantExpr::create(len == 0 ? kind : len, klee::Expr::Int8), opt_len_symbol[0]));
    // Remaining padding with option 1
    for (auto i = len - 2; i < opt_data_symbol.size(); i++) {
        curConstraint = klee::AndExpr::create(curConstraint, klee::EqExpr::create(
                klee::ConstantExpr::create(len == 0 ? kind : 1, klee::Expr::Int8), opt_data_symbol[i]));
    }
    return curConstraint;
}

