#include "TCPModel.h"
#include <netinet/in.h>

void TCPModel::onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) {
    g_s2e->getDebugStream(state) << "ENTERING tcp_v4_rcv.\n";
    // extract TCP header
    target_ulong sk_buff;
    if (!state->regs()->read(CPU_OFFSET(regs[skbPtrRegOff]), &sk_buff, sizeof(sk_buff), false)) {
        g_s2e->getWarningsStream(state) << "ERROR: symbolic argument was passed to tcp_v4_rcv.\n";
        exit(-1);
    }
    g_s2e->getDebugStream(state) << "sk_buff: " << s2e::hexval(sk_buff) << "\n";

    // offData2SkBuff to sk_buff->data
    target_ulong sk_buff_data;
    if (!state->mem()->read(sk_buff + offData2SkBuff, &sk_buff_data, sizeof(sk_buff_data))) {
        g_s2e->getWarningsStream(state) << "ERROR: couldn't read memory for sk_buff_data at "
                                        << s2e::hexval(sk_buff + offData2SkBuff) << "\n";
        exit(-1);
    }
    g_s2e->getDebugStream(state) << "offData2SkBuff: " << offData2SkBuff << ", sk_buff->data: "
                                 << s2e::hexval(sk_buff_data) << "\n";

    uint16_t sport, dport;
    if (!state->mem()->read(sk_buff_data + offSport2Data, &sport, sizeof(sport))) {
        g_s2e->getWarningsStream(state) << "ERROR: couldn't read src port " << s2e::hexval(sk_buff_data + offSport2Data)
                                        << "\n";
        exit(-1);
    }
    sport = ntohs(sport);
    if (!state->mem()->read(sk_buff_data + offDport2Data, &dport, sizeof(dport))) {
        g_s2e->getWarningsStream(state) << "ERROR: couldn't read dst port " << s2e::hexval(sk_buff_data + offSport2Data)
                                        << "\n";
        exit(-1);
    }
    dport = ntohs(dport);
    g_s2e->getDebugStream(state) << "TCP src port: " << sport << ", dst port: " << dport << "\n";

    uint32_t seq_num;
    if (!state->mem()->read(sk_buff_data + offSeq2Data, &seq_num, sizeof(seq_num))) {
        g_s2e->getWarningsStream(state) << "ERROR: couldn't read seq num " << s2e::hexval(sk_buff_data + offSeq2Data)
                                        << "\n";
        exit(-1);
    }
    g_s2e->getDebugStream(state) << "TCP seq num: " << s2e::hexval(htonl(seq_num)) << "\n";

    // symbolize TCP packet header fields
    scd->makeSymbolic(state, sk_buff_data + offSeq2Data, 4, "tcp_seq_num");
    scd->makeSymbolic(state, sk_buff_data + offAck2Data, 4, "tcp_ack_num");
    //scd->makeSymbolic(state, sk_buff_data + 12, 1, "tcp_doff_reserved_flags");
    scd->makeSymbolic(state, sk_buff_data + offFlags2Data, 1, "tcp_flags");
    scd->makeSymbolic(state, sk_buff_data + offWin2Data, 2, "tcp_win");
    //scd->makeSymbolic(state, sk_buff_data + 16, 2, "tcp_csum");
    scd->makeSymbolic(state, sk_buff_data + offUrgPtr2Data, 2, "tcp_urg_ptr");
//    if (m_symbolicTCPOptionsLength > 0) {
//        scd->makeSymbolic(state, sk_buff_data + 20, m_symbolicTCPOptionsLength,
//                            "tcp_options");
//    } else if (m_symbolicTCPOptionsStart > 0 && m_symbolicTCPOptionsEnd > 0 &&
//               m_symbolicTCPOptionsEnd - m_symbolicTCPOptionsStart > 0) {
//        scd->makeSymbolic(state, sk_buff_data + 20 + m_symbolicTCPOptionsStart,
//                            m_symbolicTCPOptionsEnd - m_symbolicTCPOptionsStart,
//                            "tcp_options");
//    }
    // symbolize the port number
    std::string sportSymbolName;
    std::vector<klee::ref<klee::Expr>> sport_symbol;
    std::string dportSymbolName;
    scd->makeSymbolic(state, sk_buff_data + offSport2Data, 2, "tcp_sport", &sport_symbol, &sportSymbolName);
    std::vector<klee::ref<klee::Expr>> dport_symbol;
    scd->makeSymbolic(state, sk_buff_data + offDport2Data, 2, "tcp_dport", &dport_symbol, &dportSymbolName);
    // symbolize src ip
    scd->makeSymbolic(state, sk_buff_data + offIpAddrLastB2Data, 1, ipOwnerName, &saddr_last_byte_symbol,
                      &ipOwnerSymbolName);
    assert(sport_symbol.size() == 2 && dport_symbol.size() == 2 && saddr_last_byte_symbol.size() == 1 &&
           "symbolize failed.");
    g_s2e->getDebugStream(state) << "ip owner raw name=" << ipOwnerSymbolName << "\n";

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
    auto srcPort_eq_0 = klee::EqExpr::create(sport_symbol[0],
                                             klee::ConstantExpr::create(*((uint8_t *) &srcport), klee::Expr::Int8));
    auto srcPort_eq_1 = klee::EqExpr::create(sport_symbol[1], klee::ConstantExpr::create(*(((uint8_t *) &srcport) + 1),
                                                                                         klee::Expr::Int8));
    auto atkr_dstPort_eq_0 = klee::EqExpr::create(dport_symbol[0],
                                                  klee::ConstantExpr::create(*((uint8_t *) &attackerDstPort),
                                                                             klee::Expr::Int8));
    auto atkr_dstPort_eq_1 = klee::EqExpr::create(dport_symbol[1],
                                                  klee::ConstantExpr::create(*(((uint8_t *) &attackerDstPort) + 1),
                                                                             klee::Expr::Int8));
    auto vctm_dstPort_eq_0 = klee::EqExpr::create(dport_symbol[0],
                                                  klee::ConstantExpr::create(*((uint8_t *) &victimDstPort),
                                                                             klee::Expr::Int8));
    auto vctm_dstPort_eq_1 = klee::EqExpr::create(dport_symbol[1],
                                                  klee::ConstantExpr::create(*(((uint8_t *) &victimDstPort) + 1),
                                                                             klee::Expr::Int8));
    auto ne_dstPort_eq_0 = klee::EqExpr::create(dport_symbol[0],
                                                klee::ConstantExpr::create(*((uint8_t *) &nonExistDsrPort),
                                                                           klee::Expr::Int8));
    auto ne_dstPort_eq_1 = klee::EqExpr::create(dport_symbol[1],
                                                klee::ConstantExpr::create(*(((uint8_t *) &nonExistDsrPort) + 1),
                                                                           klee::Expr::Int8));
    auto attacker_constraints = klee::AndExpr::create(ip_attacker_eq, klee::OrExpr::create(
            klee::AndExpr::create(atkr_dstPort_eq_0, atkr_dstPort_eq_1),
            klee::AndExpr::create(ne_dstPort_eq_0, ne_dstPort_eq_1)));
    auto victim_constraints = klee::AndExpr::create(ip_victim_eq,
                                                    klee::AndExpr::create(vctm_dstPort_eq_0, vctm_dstPort_eq_1));

    // add constraints
    assert(scd->addConstraint(state, klee::AndExpr::create(klee::AndExpr::create(srcPort_eq_0, srcPort_eq_1),
                                                           klee::OrExpr::create(attacker_constraints,
                                                                                victim_constraints)),
                              "init constraints") &&
           "add initial constraints failed.\n");

    g_s2e->getDebugStream(state) << "TCP packet header symbolized.\n";

    // Remove skb->sk to prevent "stealing" sk, see __inet_lookup_skb(). This is to ensure we have both attacker's and victim's path
    uint64_t skb_sk_ptr = 0;
    state->mem()->write(sk_buff + offSkPtr2Skb, &skb_sk_ptr, sizeof(skb_sk_ptr));
//    scd->disallowedGWRanges.emplace_back(sk_buff + offSkPtr2Skb, sk_buff + offSkPtr2Skb + sizeof(skb_sk_ptr) - 1, 0);
    // Also remove destructor to avoid kernel panic
    uint64_t skb_destructor_ptr = 0;
    state->mem()->write(sk_buff + offDestructorPtr2Skb, &skb_destructor_ptr, sizeof(skb_destructor_ptr));
//    scd->disallowedGWRanges.emplace_back(sk_buff + offDestructorPtr2Skb,
//                                         sk_buff + offDestructorPtr2Skb + sizeof(skb_destructor_ptr) - 1, 0);


    // Since we've symbolized all inputs, block symbolizing on remaining fields
    // From skb->data to skb->tail
    uint64_t sk_buff_head;
    if (!state->mem()->read(sk_buff + offSkbHeadPtr2Skb, &sk_buff_head, sizeof(sk_buff_head))) {
        g_s2e->getWarningsStream(state) << "ERROR: couldn't read memory for sk_buff_head at "
                                        << s2e::hexval(sk_buff + offSkbHeadPtr2Skb) << "\n";
        exit(-1);
    }
    uint32_t sk_buff_end_offset_to_head;
    if (!state->mem()->read(sk_buff + off_OffSkbEnd2SkbHead_2_Skb, &sk_buff_end_offset_to_head,
                            sizeof(sk_buff_end_offset_to_head))) {
        g_s2e->getWarningsStream(state) << "ERROR: couldn't read memory for sk_buff_end_offset_to_head at "
                                        << s2e::hexval(sk_buff + off_OffSkbEnd2SkbHead_2_Skb) << "\n";
        exit(-1);
    }
    scd->disallowedGWRanges.emplace_back(sk_buff_head, sk_buff_head + sk_buff_end_offset_to_head - 1, 0);
    g_s2e->getDebugStream(state) << "Input address range 0: " << s2e::hexval(sk_buff_head) << " - "
                                 << s2e::hexval(sk_buff_head + sk_buff_end_offset_to_head) << "\n";

    // From skb to the end of skb
    scd->disallowedGWRanges.emplace_back(sk_buff, sk_buff + skbSize - 1, 0);
    g_s2e->getDebugStream(state) << "Input address range 1: " << s2e::hexval(sk_buff) << " - "
                                 << s2e::hexval(sk_buff + skbSize - 1) << "\n";

    // slow down clock
    //*g_sqi.exec.clock_scaling_factor = 10000;

    // byass checksum validation by setting ip_summed to CHECKSUM_UNNECESSARY
    unsigned char byte;
    state->mem()->read(sk_buff + offIpSummed2Skb, &byte, sizeof(byte));
    // clear the bits
    byte &= ~(3 << offIpSummedBit);
    // set the bits
    byte |= 1 << offIpSummedBit;
    state->mem()->write(sk_buff + offIpSummed2Skb, &byte, sizeof(byte));
    g_s2e->getDebugStream(state) << "Setting skb->ip_summed to CHECKSUM_UNNECESSARY: " << s2e::hexval(byte) << "\n";

    state->regs()->write(CPU_OFFSET(timer_interrupt_disabled), 1);
    state->regs()->write(CPU_OFFSET(all_apic_interrupts_disabled), 1);

    // Sort disallowed GW
    if (!s2e::plugins::Propagator::Range::sortRanges(scd->disallowedGWRanges)) {
        g_s2e->getWarningsStream() << "disallowedGWRanges contains overlap!\n";
        exit(-1);
    }
}

s2e::plugins::GlobalWrite2 TCPModel::onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) {
    uint64_t skbPtr;
    auto isCon = state->regs()->read(CPU_OFFSET(regs[outputSkbPtrRegOff]), &skbPtr, 8, false);    // 8 bytes
    if (!isCon) {
        auto sym = state->regs()->read(CPU_OFFSET(regs[outputSkbPtrRegOff]), klee::Expr::Int64);
        if (state->regs()->read(CPU_OFFSET(regs[outputSkbPtrRegOff]), &skbPtr, 8, true)) {
            g_s2e->getDebugStream(state) << "concretizing skbPtr on output function pc=" << s2e::hexval(pc) << ", skb="
                                         << s2e::hexval(skbPtr) << "\n";
            scd->addConstraint(state, klee::EqExpr::create(sym, klee::ConstantExpr::create(skbPtr, klee::Expr::Int64)),
                               "output skbPtr");
        } else {
            g_s2e->getDebugStream(state) << "Failed to concretize skbPtr on output function pc=" << s2e::hexval(pc)
                                         << ", skb=\n"
                                         << state->regs()->read(CPU_OFFSET(regs[outputSkbPtrRegOff]),
                                                                klee::Expr::Int64);
            return {};
        }
    }

    bool err = false;
    // &(skb->head) - skb
    auto headPtr = scd->readAndConcretizeMemory64(state, skbPtr + offSkbHeadPtr2Skb, err,
                                                  "&(skb->head) - skb");   // skb->head
    if (err) {
        g_s2e->getDebugStream(state) << "Failed to access skb->head on output function pc=" << s2e::hexval(pc)
                                     << ", &(skb->head)=\n" << s2e::hexval(skbPtr + offSkbHeadPtr2Skb);
        return {};
    }


    // &(skb->transport_header) - skb
    // Workaround
    auto transportPtr = scd->readAndConcretizeMemory16(state, skbPtr + offTransportHdr2Skb, err,
                                                       "&(skb->transport_header) - skb");   // skb->transport_header
    if (err) {
        g_s2e->getDebugStream(state) << "Failed to access skb->transportPtr on output function pc=" << s2e::hexval(pc)
                                     << ", &(skb->transportPtr)=\n" << s2e::hexval(skbPtr + offTransportHdr2Skb);
        return {};
    }

    uint64_t tcpHdrPtr = headPtr + transportPtr;  // skb->head + skb->transport_header
    auto tcpHdr = s2e::plugins::Propagator::extendedRead(state, tcpHdrPtr, tcpHdrSize * 8); // 160 bits
    if (tcpHdr.isNull()) { // 8 bytes
        g_s2e->getDebugStream(state) << "Failed to access *(skb->head + skb->transportPtr) on output function pc="
                                     << s2e::hexval(pc) << ", skb->head + skb->transportPtr=\n"
                                     << s2e::hexval(tcpHdrPtr);
        return {};
    }

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

uint8_t
TCPModel::getNewStateOwner(s2e::S2EExecutionState *oldState, s2e::S2EExecutionState *newState,
                           const std::vector<klee::ref<klee::Expr>> &newCond, s2e::plugins::Propagator *scd,
                           uint8_t oldOwner) {
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
            scd->onTimeout(newState, s2e::CorePlugin::TimeoutReason::SOLVER);
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
            scd->onTimeout(newState, s2e::CorePlugin::TimeoutReason::SOLVER);
        }
    }


//    for (const auto &it: newState->concolics->bindings) {
//        if (it.first->getName() == ipOwnerSymbolName) {
//            klee::ArrayVec arrayVec;
//            arrayVec.push_back(it.first);
//            std::vector<std::vector<unsigned char>> value;
//            value.emplace_back();
//            // Check if another owner is possible
//            if (it.second[0] == attackerIPLastB) {
//                value[0].push_back(victimIPLastB);
//            } else {
//                value[0].push_back(attackerIPLastB);
//            }
//            klee::Assignment assignment(arrayVec, value);
//            // Note this also includes solver timeout, in which case we narrow down the owner scope
//            if (!newState->solve(newState->constraints(), assignment)) {
//                if (it.second[0] == attackerIPLastB) {
//                    newOwner &= ~victimOwner;
//                } else {
//                    newOwner &= ~attackerOwner;
//                }
//            }
//            break;
//        }
//    }

    // If no symbol was found, return newOwner=3
    if (newOwner != oldOwner) {
        g_s2e->getDebugStream(newState) << "Owner changed from " << (uint) oldOwner << " to " << (uint) newOwner
                                        << "\n";
    }

//    bool freeSymbolHasIPOwner = false;
//    for (const auto &s: oldState->freeSymbols) {
//        if (s->getName() == ipOwnerSymbolName) {
//            freeSymbolHasIPOwner = true;
//            g_s2e->getDebugStream(oldState) << "forking on IP owner\n";
//            break;
//        }
//    }
//    if (!freeSymbolHasIPOwner) {
//        return oldOwner;
//    }
//    uint8_t newOwner = 0;
//    bool found = false;
//    for (const auto &it: newState->concolics->bindings) {
//        if (it.first->getName() == ipOwnerSymbolName) {
//            found = true;
//            // got the concolic binding
//            bool curBindingIsAtkr = (it.second[0] == attackerIPLastB);
//            newOwner |= (curBindingIsAtkr ? attackerOwner : victimOwner);
//            // check if another is possible
//            auto evalResult = newState->concolics->evaluate(klee::EqExpr::create(
//                    klee::ReadExpr::create(klee::UpdateList::create(it.first, 0),
//                                           klee::ConstantExpr::create(0, klee::Expr::Int32)),
//                    curBindingIsAtkr ? klee::ConstantExpr::create(victimIPLastB, klee::Expr::Int8)
//                                     : klee::ConstantExpr::create(attackerIPLastB, klee::Expr::Int8)));
//            auto *ce = dyn_cast<klee::ConstantExpr>(evalResult);
//            check(ce, "Could not evaluate the expression to a constant.");
//            if (ce->isTrue()) {
//                newOwner |= (curBindingIsAtkr ? victimOwner : attackerOwner);
//            }
//            break;
//        }
//    }
//    assert(found);
    return newOwner;
}

TCPModel::TCPModel(s2e::plugins::Propagator *scd) : ProtocolModel(scd) {
    attackerOwner = 0b01;
    victimOwner = 0b10;
    defaultOwner = attackerOwner | victimOwner;
    srcport = htobe16(9638);
    attackerDstPort = htobe16(5555);
    victimDstPort = htobe16(6666);
    nonExistDsrPort = htobe16(7777);
}