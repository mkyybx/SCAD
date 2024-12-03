#ifndef SCDETECTOR2_KNOWNRESULTS_H
#define SCDETECTOR2_KNOWNRESULTS_H

#include <shared_mutex>
#include "BasicType.h"

using namespace std;

// TODO check high-order thread safety like test-and-set using getPropagationStatus and setPropagationStatus is not safe
namespace SCDetector {
    class KnownResults {
    public:
        enum class PropagationStatus {
            NOT_FOUND,  // This must be 0 as it's the default value for init
            PROVED,
            DISALLOWED,
        };

        void setPropagationStatus(uint8_t owner, const shared_ptr<Symbol> &from, const shared_ptr<Symbol> &to,
                                  PropagationStatus status);

        void addDisallowedFrom(const shared_ptr<Symbol> &from, uint8_t owner);

        void addDisallowedTo(const shared_ptr<Symbol> &to, uint8_t owner);

        bool isPropagationAllowed(uint8_t owner, const shared_ptr<Symbol> &from, const shared_ptr<Symbol> &to);

        PropagationStatus
        getPropagationStatus(uint8_t owner, const shared_ptr<Symbol> &from, const shared_ptr<Symbol> &to);

        bool
        compareAndExchangePropagationStatus(uint8_t owner, const shared_ptr<Symbol> &from, const shared_ptr<Symbol> &to,
                                            PropagationStatus expected, PropagationStatus desired);

        KnownResults(const shared_ptr<FkgHeads> &fkgHead, const shared_ptr<Symbols> &symbols);

#ifdef NO_MED_TO_MED
/*
        void addSecNodesCount(const shared_ptr<Symbol> &secSymbol);

        void reduceSecNodesCount(const shared_ptr<Symbol> &secSymbol);

        void addPartialPathCount(const shared_ptr<Symbol> &from, const shared_ptr<Symbol> &to);

        void reducePartialPathCount(const shared_ptr<SideChannelPropagation> &prop);

        void addInvalidSymbol(const shared_ptr<Symbol> &symbol);
*/
#endif
    private:
        const shared_ptr<Symbols> symbols;
        const shared_ptr<FkgHeads> fkgHead;
        unordered_map<uint8_t, unordered_map<shared_ptr<Symbol>, unordered_map<shared_ptr<Symbol>, atomic<PropagationStatus>>>> propagationsStatus; // Owner->from->to
        atomic<uint64_t> validSymbols;
#ifdef NO_MED_TO_MED
/*
        unordered_map<shared_ptr<Symbol>, atomic<uint64_t>> secNodeCountPerSymbol;
        unordered_map<shared_ptr<Symbol>, atomic<uint64_t>> checkedSecNodeCountPerSymbol;
        unordered_map<shared_ptr<Symbol>, unordered_map<shared_ptr<Symbol>, atomic<uint64_t>>> fromToTotalSCPPCount;
        unordered_map<shared_ptr<Symbol>, unordered_map<shared_ptr<Symbol>, atomic<uint64_t>>> fromToCheckedSCPPCount;
        unordered_set<shared_ptr<Symbol>> invalidSymbols;

        shared_mutex _lock;

        void checkLevel2Impossible(const shared_ptr<Symbol> &fromSymbol, const shared_ptr<Symbol> &toSymbol);

        void checkLevel1Impossible(const shared_ptr<Symbol> &secSymbol);
*/
#endif
    };
} // SCDetector

#endif //SCDETECTOR2_KNOWNRESULTS_H
