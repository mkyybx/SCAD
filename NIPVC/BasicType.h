#ifndef SCDETECTOR2_BASICTYPE_H
#define SCDETECTOR2_BASICTYPE_H

#include <boost/serialization/access.hpp>
#include <cstdint>
#include <string>
#include <memory>
#include <unordered_set>
#include "GlobalVariables.h"
#include "SolverManager.h"
#include "Using.h"

using namespace std;
namespace SCDetector {
    class Path {
    private:
        friend class boost::serialization::access;

        template<class Archive>
        void serialize(Archive &ar, const unsigned int) {
            ar & pathNum;
            ar & owner;
        }

    public:
        uint64_t pathNum;
        uint8_t owner;
    };

    class ForkPoint {
    private:
        friend class boost::serialization::access;

        template<class Archive>
        void serialize(Archive &ar, const unsigned int) {
            ar & cond;
            ar & parent;
            ar & left;
            ar & right;
            ar & fromFkid;
            ar & leftFkid;
            ar & rightFkid;
            ar & pathNum;
            ar & pc;
            ar & owner;
        }

    public:
        string cond;
        shared_ptr<ForkPoint> parent;
        shared_ptr<ForkPoint> left;
        shared_ptr<ForkPoint> right;
        uint64_t fromFkid = FKP_KILL_END;
        uint64_t leftFkid = FKP_KILL_END;
        uint64_t rightFkid = FKP_KILL_END;
        uint64_t pathNum;
        uint64_t pc;
        uint8_t owner;

        static shared_ptr<ForkPoint> makeNode(uint64_t fromFkid, const shared_ptr<ForkPoint> &parent, uint64_t nextFkid);
    };

    class ParsedGW {
    private:
        friend class boost::serialization::access;

        template<class Archive>
        void serialize(Archive &ar, const unsigned int) {
            ar & vars;
            ar & expr;
        }

    public:
        unordered_set<string> vars;
        shared_ptr<unordered_set<uint64_t>> varAddrs;
        string expr;

        /**
         *  Loose overload used for std::map. We only compare the query string instead of putting two queries into the solver and check if there is a common space for them to be not equal.
         */
        bool operator<(const ParsedGW &other) const;

        bool operator==(const ParsedGW &other) const;

        bool operator!=(const ParsedGW &other) const;

        bool operator>(const ParsedGW &other) const;
    };

    class GlobalWrite {
    private:
        friend class boost::serialization::access;

        template<class Archive>
        void serialize(Archive &ar, const unsigned int) {
            ar & addr;
            ar & size;
            ar & out;
            ar & summary;
            ar & pathNum;
            ar & fromFkid;
            ar & pc;
        }

    public:
        uint64_t addr;
        uint16_t size;
        bool out;
        ParsedGW summary;
        uint64_t pathNum;
        uint64_t fromFkid;
        uint64_t pc;

        static shared_ptr<GlobalWrite> gwNA;
        static shared_ptr<GlobalWrite> gwNoWrite;

        static void addDiffGWQueryToSolver(const shared_ptr<SolverBundle> &bundle, const shared_ptr<GlobalWrite> &gw0,
                                           const shared_ptr<GlobalWrite> &gw1);

        static void init();
    };

    class Symbol {
    private:
        friend class boost::serialization::access;

        template<class Archive>
        void serialize(Archive &ar, const unsigned int) {
            ar & addr;
            ar & size;
            ar & initVal;
            ar & pc;
            ar & state;
            ar & name;
            ar & addrStr;
            ar & defaultGW;
        }

        void buildDefaultGW();

        Symbol() = default;

    public:
        uint64_t addr;
        uint8_t size;
        uint64_t initVal;
        uint64_t pc;
        uint64_t state;
        string name;
        string addrStr;
        shared_ptr<GlobalWrite> defaultGW;
        static shared_ptr<Symbol> outputSymbol;

        Symbol(uint64_t addr, uint8_t size, uint64_t initVal, uint64_t pc, uint64_t state, string name);

        static void init();
    };

    class PartialPath {
    private:
        friend class boost::serialization::access;

        template<class Archive>
        void serialize(Archive &ar, const unsigned int) {
            ar & gw;    // TODO: high memory usage?
            ar & top;
            ar & bottom;
        }

        PartialPath() = default;

        static shared_ptr<unordered_map<uint64_t, unordered_map<uint64_t, shared_ptr<GlobalWrite>>>> fkid2GWS;
    public:
        GWSet gw; // This is for storing multiple GWs for common partial paths
        shared_ptr<ForkPoint> top;
        shared_ptr<ForkPoint> bottom; // Note this bottom's condition is not useful. We only care about the edges to draw the constraints.

        PartialPath(const shared_ptr<ForkPoint> &top, const shared_ptr<ForkPoint> &bottom); // For parent partial paths

        PartialPath(const shared_ptr<GlobalWrite> &gw, const shared_ptr<ForkPoint> &top,
                    const shared_ptr<ForkPoint> &bottom);   // For normal partial paths

        void addToSolver(const shared_ptr<SolverBundle> &bundle, const string &secNameToReplace) const;

        static void setFkid2Gws(
                const shared_ptr<unordered_map<uint64_t, unordered_map<uint64_t, shared_ptr<GlobalWrite>>>> &fkid2Gws);
    };

    class DirectPropagation {
    private:
        friend class boost::serialization::access;

        template<class Archive>
        void serialize(Archive &ar, const unsigned int) {
            ar & gws;
            ar & secNode;
            ar & bottomNode;
            ar & gwUsedForModelQuery;
        }

        DirectPropagation() = default;

    public:
        DirectPropagation(const shared_ptr<unordered_set<shared_ptr<GlobalWrite>>> &gws,
                          const shared_ptr<ForkPoint> &secNode, const shared_ptr<ForkPoint> &bottomNode,
                          const shared_ptr<GlobalWrite> &gwUsedForModelQuery);

        shared_ptr<unordered_set<shared_ptr<GlobalWrite>>> gws;
        shared_ptr<ForkPoint> secNode;
        shared_ptr<ForkPoint> bottomNode;
        shared_ptr<GlobalWrite> gwUsedForModelQuery;
    };

    enum class PropagationType {
        CK_SEC_ONE,
        CK_SEC_TWO,
        CK_SEC_DIRECT,
        CK_MED_ONE,
        CK_MED_TWO,
        CK_MED_DIRECT,
        CK_OUT_ONE,
        CK_OUT_TWO,
        CK_OUT_DIRECT,
        CK_NUM_TYPES,
    };

    class SideChannelPropagation {
    private:
        friend class boost::serialization::access;

        template<class Archive>
        void serialize(Archive &ar, const unsigned int) {
            ar & pp;
            ar & directPropagation;
            ar & commonPartialPath;
            ar & from;
            ar & to;
            ar & owner;
            ar & propagationType;
        }

        // private for boost
        SideChannelPropagation() = default;

    public:
        PartialPathPair pp;
        shared_ptr<PartialPath> commonPartialPath;
        shared_ptr<DirectPropagation> directPropagation;
        const shared_ptr<Symbol> from;
        const shared_ptr<Symbol> to;
        uint8_t owner;
        PropagationType propagationType;
        static shared_ptr<FkgHeads> fkgHeads;

        SideChannelPropagation(const shared_ptr<PartialPath> &pp0, const shared_ptr<PartialPath> &pp1,
                               const shared_ptr<PartialPath> &commonPartialPath, const shared_ptr<Symbol> &from,
                               const shared_ptr<Symbol> &to, uint8_t owner);

        SideChannelPropagation(const shared_ptr<PartialPath> &commonPartialPath,
                               const shared_ptr<DirectPropagation> &directPropagation, const shared_ptr<Symbol> &from,
                               const shared_ptr<Symbol> &to, uint8_t owner);

        SolverCheckResult buildModel(shared_ptr<SolverBundle> &bundle);

        SolverCheckResult checkSat(shared_ptr<SolverBundle> &bundle);

        static shared_ptr<DijkstraPropagationMap> toDijkstraMap(const PropagationMap &input);

        static void setFkgHeads(const shared_ptr<FkgHeads> &fkgHeads);

        static shared_ptr<SideChannelPropagation> dummyProp;

        static void init();
    };

    class SideChannelPropagations {
    private:
        friend class boost::serialization::access;

        template<class Archive>
        void serialize(Archive &ar, const unsigned int) {
            ar & hasDirectPropagation;
            ar & propagations;
        }

    public:
        bool hasDirectPropagation = false;
        vector<shared_ptr<SideChannelPropagation>> propagations;

        SideChannelPropagations() = default;
    };
}


namespace std {
    ostream &operator<<(ostream &os, const SCDetector::GlobalWrite &gw);

    ostream &operator<<(ostream &os, const SCDetector::ParsedGW &summary);

    ostream &operator<<(ostream &os, const SCDetector::Symbol &symbol);
}


#endif //SCDETECTOR2_BASICTYPE_H
