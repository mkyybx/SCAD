#include "UDPModel.h"

void UDPModel::onEntryFunction(s2e::S2EExecutionState *state, uint64_t pc) {
    g_s2e->getDebugStream(state) << "ENTERING __udp4_lib_rcv.\n";
    // get udp_hdr
    uint64_t skbPtr;
    if (!scd->readRegister64(state, skbPtrRegOff, &skbPtr, "udp header for entry function")) {
        exit(-1);
    }
    bool err = false;
    // &(skb->head) - skb
    auto headPtr = scd->readAndConcretizeMemory64(state, skbPtr + offSkbHeadPtr2Skb, err,
                                                  "&(skb->head) - skb");   // skb->head
    if (err) {
        g_s2e->getDebugStream(state) << "Failed to access skb->head on output function pc=" << s2e::hexval(pc)
                                     << ", &(skb->head)=\n" << s2e::hexval(skbPtr + offSkbHeadPtr2Skb);
        exit(-1);
    }
    // &(skb->transport_header) - skb
    auto transportOff2Head = scd->readAndConcretizeMemory16(state, skbPtr + offTransportHdr2Skb, err,
                                                            "&(skb->transport_header) - skb");   // skb->transport_header
    if (err) {
        g_s2e->getDebugStream(state) << "Failed to access skb->transportOff2Head on output function pc="
                                     << s2e::hexval(pc) << ", &(skb->transportOff2Head)=\n"
                                     << s2e::hexval(skbPtr + offTransportHdr2Skb);
        exit(-1);
    }
    uint64_t udpHdrPtr = headPtr + transportOff2Head;  // skb->head + skb->transport_header

    // &(skb->network_header) - skb
    auto networkOff2Head = scd->readAndConcretizeMemory16(state, skbPtr + offNetworkHdr2Skb, err,
                                                          "&(skb->network_header) - skb");
    if (err) {
        g_s2e->getDebugStream(state) << "Failed to access skb->networkOff2Head on output function pc="
                                     << s2e::hexval(pc) << ", &(skb->networkOff2Head)=\n"
                                     << s2e::hexval(skbPtr + offNetworkHdr2Skb);
        exit(-1);
    }
    uint64_t ipHdrPtr = headPtr + networkOff2Head;  // skb->head + skb->network_header

    // symbolize fields
    std::string sportSymbolName;
    std::vector<klee::ref<klee::Expr>> sport_symbol;
    scd->makeSymbolic(state, udpHdrPtr + offSport, 2, "sport", &sport_symbol, &sportSymbolName);
    std::string dportSymbolName;
    std::vector<klee::ref<klee::Expr>> dport_symbol;
    scd->makeSymbolic(state, udpHdrPtr + offDport, 2, "dport", &dport_symbol, &dportSymbolName);
    scd->makeSymbolic(state, udpHdrPtr + offLen, 2, "len");
    scd->makeSymbolic(state, ipHdrPtr + offSrcIPLastB2IpHdr, 1, ipOwnerName, &saddr_last_byte_symbol,
                      &ipOwnerSymbolName);

    // allow symbolic pointer forking to distingusih the owner
    symbolicPointerForkingSymbolNames.insert(sportSymbolName);
    symbolicPointerForkingSymbolNames.insert(dportSymbolName);
    symbolicPointerForkingSymbolNames.insert(ipOwnerSymbolName);

    // build constraints
    auto ip_victim_eq = klee::EqExpr::create(saddr_last_byte_symbol[0],
                                             klee::ConstantExpr::create(victimIPLastB, klee::Expr::Int8));
    auto ip_attacker_eq = klee::EqExpr::create(saddr_last_byte_symbol[0],
                                               klee::ConstantExpr::create(attackerIPLastB, klee::Expr::Int8));
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
    auto listen_dstPort_eq_0 = klee::EqExpr::create(dport_symbol[0],
                                                    klee::ConstantExpr::create(*((uint8_t *) &listenDsrPort),
                                                                               klee::Expr::Int8));
    auto listen_dstPort_eq_1 = klee::EqExpr::create(dport_symbol[1],
                                                    klee::ConstantExpr::create(*(((uint8_t *) &listenDsrPort) + 1),
                                                                               klee::Expr::Int8));
    auto srcPortConstraints = klee::AndExpr::create(srcPort_eq_0, srcPort_eq_1);
    auto commonDstPortConstraints = klee::OrExpr::create(klee::AndExpr::create(ne_dstPort_eq_0, ne_dstPort_eq_1),
                                                         klee::AndExpr::create(listen_dstPort_eq_0,
                                                                               listen_dstPort_eq_1));
    auto attacker_constraints = klee::AndExpr::create(ip_attacker_eq, klee::AndExpr::create(srcPortConstraints,
                                                                                            klee::OrExpr::create(
                                                                                                    commonDstPortConstraints,
                                                                                                    klee::AndExpr::create(
                                                                                                            atkr_dstPort_eq_0,
                                                                                                            atkr_dstPort_eq_0))));
    auto victim_constraints = klee::AndExpr::create(ip_victim_eq, klee::AndExpr::create(srcPortConstraints,
                                                                                        klee::OrExpr::create(
                                                                                                commonDstPortConstraints,
                                                                                                klee::AndExpr::create(
                                                                                                        vctm_dstPort_eq_0,
                                                                                                        vctm_dstPort_eq_1))));

    // add constraints
    assert(scd->addConstraint(state, klee::OrExpr::create(attacker_constraints, victim_constraints),
                              "init constraints") && "add initial constraints failed.\n");

    g_s2e->getDebugStream(state) << "UDP packet header symbolized. Current concolics is=\n"
                                 << state->concolics->evaluate(scd->extendedRead(state, udpHdrPtr, udpIcmpHdrSize * 8))
                                 << "\n";

    // Remove skb->sk to prevent "stealing" sk. This is to ensure we have both attacker's and victim's path
    uint64_t skb_sk_ptr = 0;
    state->mem()->write(skbPtr + offSkPtr2Skb, &skb_sk_ptr, sizeof(skb_sk_ptr));
    // Also remove destructor to avoid kernel panic
    uint64_t skb_destructor_ptr = 0;
    state->mem()->write(skbPtr + offDestructorPtr2Skb, &skb_destructor_ptr, sizeof(skb_destructor_ptr));

    // Since we've symbolized all inputs, block symbolizing on remaining fields
    // From skb->data to skb->tail
    uint32_t sk_buff_end_offset_to_head;
    if (!state->mem()->read(skbPtr + off_OffSkbEnd2SkbHead_2_Skb, &sk_buff_end_offset_to_head,
                            sizeof(sk_buff_end_offset_to_head))) {
        g_s2e->getWarningsStream(state) << "ERROR: couldn't read memory for sk_buff_end_offset_to_head at "
                                        << s2e::hexval(skbPtr + off_OffSkbEnd2SkbHead_2_Skb) << "\n";
        exit(-1);
    }
    scd->disallowedGWRanges.emplace_back(headPtr, headPtr + sk_buff_end_offset_to_head - 1, 0);
    g_s2e->getDebugStream(state) << "Input address range 0: " << s2e::hexval(headPtr) << " - "
                                 << s2e::hexval(headPtr + sk_buff_end_offset_to_head) << "\n";

    // From skb to the end of skb
    scd->disallowedGWRanges.emplace_back(skbPtr, skbPtr + skbSize - 1, 0);
    g_s2e->getDebugStream(state) << "Input address range 1: " << s2e::hexval(skbPtr) << " - "
                                 << s2e::hexval(skbPtr + skbSize - 1) << "\n";

    // byass checksum validation by setting ip_summed to CHECKSUM_UNNECESSARY
    unsigned char byte;
    state->mem()->read(skbPtr + offIpSummed2Skb, &byte, sizeof(byte));
    // clear the bits
    byte &= ~(3 << offIpSummedBit);
    // set the bits
    byte |= 1 << offIpSummedBit;
    state->mem()->write(skbPtr + offIpSummed2Skb, &byte, sizeof(byte));
    g_s2e->getDebugStream(state) << "Setting skb->ip_summed to CHECKSUM_UNNECESSARY: " << s2e::hexval(byte) << "\n";

    state->regs()->write(CPU_OFFSET(timer_interrupt_disabled), 1);
    state->regs()->write(CPU_OFFSET(all_apic_interrupts_disabled), 1);

    // Sort disallowed GW
    if (!s2e::plugins::Propagator::Range::sortRanges(scd->disallowedGWRanges)) {
        g_s2e->getWarningsStream() << "disallowedGWRanges contains overlap!\n";
        exit(-1);
    }
}

s2e::plugins::GlobalWrite2 UDPModel::onOutputFunction(s2e::S2EExecutionState *state, uint64_t pc) {
    uint64_t skbPtr;
    if (!scd->readRegister64(state, outSkbPtrRegOff, &skbPtr, "udp header for output function")) {
        return {};
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
    auto transportPtrOff2Hread = scd->readAndConcretizeMemory16(state, skbPtr + offTransportHdr2Skb, err,
                                                                "&(skb->transport_header) - skb");   // skb->transport_header
    if (err) {
        g_s2e->getDebugStream(state) << "Failed to access skb->transportPtrOff2Hread on output function pc="
                                     << s2e::hexval(pc)
                                     << ", &(skb->transportPtrOff2Hread)=\n"
                                     << s2e::hexval(skbPtr + offTransportHdr2Skb);
        return {};
    }

    uint64_t hdrPtr = headPtr + transportPtrOff2Hread;  // skb->head + skb->transport_header
    auto hdr = s2e::plugins::Propagator::extendedRead(state, hdrPtr, udpIcmpHdrSize * 8);
    if (hdr.isNull()) { // 8 bytes
        g_s2e->getDebugStream(state) << "Failed to access *(headPtr + transportPtrOff2Hread) on output function pc="
                                     << s2e::hexval(pc) << ", headPtr + transportPtrOff2Hread=\n"
                                     << s2e::hexval(hdrPtr);
        return {};
    }

    auto tmp = s2e::plugins::GlobalWrite2();
    tmp.size = udpIcmpHdrSize;
    tmp.isOutput = true;
    tmp.pc = pc;
    tmp.summary = hdr;
    tmp.cAddr = hdrPtr;
    tmp.stateID = state->getID();
    tmp.isPcPrecise = true;

    return tmp;
}

uint8_t
UDPModel::getNewStateOwner(s2e::S2EExecutionState *oldState, s2e::S2EExecutionState *newState,
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
            return 0;
//            scd->onTimeout(newState, s2e::CorePlugin::TimeoutReason::SOLVER);
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
//            scd->onTimeout(newState, s2e::CorePlugin::TimeoutReason::SOLVER);
        }
    }
    // If no symbol was found, return newOwner=3
    if (newOwner != oldOwner) {
        g_s2e->getDebugStream(newState) << "Owner changed from " << (uint) oldOwner << " to " << (uint) newOwner
                                        << "\n";
    }
    return newOwner;
}

UDPModel::UDPModel(s2e::plugins::Propagator *scd) : ProtocolModel(scd) {
    attackerOwner = 0b01;
    victimOwner = 0b10;
    defaultOwner = attackerOwner | victimOwner;
    srcport = htobe16(
            12345);           // Simulates to port 53 on name server. The victim client will be tricked to connect both attacker and victim server's 53.
    nonExistDsrPort = htobe16(8369);    // On victim server
    listenDsrPort = htobe16(9638);     // On victim server
}