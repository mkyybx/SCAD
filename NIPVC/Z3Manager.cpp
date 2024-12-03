#include "Z3Manager.h"
#include "GlobalVariables.h"
#include "ProgressPrinter.h"
#include "Utils.h"

using namespace std;
using namespace SCDetector;

Z3Manager::Z3Manager(uint64_t lruCacheSize) {
    for (auto i = 0; i < SCD_THREADS; i++) {
        shared_ptr<Z3Bundle> bundle;
        bundle.reset(new Z3Bundle());
        // Init cache to avoid race condition
        cache.insert(pair(bundle, LRUCache<string, z3::expr>(lruCacheSize)));
        // Init Q
        bundleQ.put(std::move(bundle));
    }
}

shared_ptr<SolverBundle> Z3Manager::getSolverBundle() {
    auto ret = bundleQ.get();
    ret->solver->push();
    return ret;
}

void Z3Manager::addSMT(const shared_ptr<SolverBundle> &genericBundle, const string &smt, bool reverse) {
    auto bundle = static_pointer_cast<Z3Bundle>(genericBundle);
    compileCount++;
    z3::expr compiledExpr = bundle->z3ctx->bool_val(true);
    if (cache.at(bundle).contains(smt)) {
        compiledExpr = cache.at(bundle).get(smt);
    } else {
        cacheMissCount++;
        auto startTime = duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        auto exprVec = bundle->z3ctx->parse_string(smt.c_str());
        assert(!exprVec.empty());
        if (exprVec.size() == 1) {
            compiledExpr = exprVec[0];
        } else {
            for (const auto &expr: exprVec) {
                compiledExpr = compiledExpr && expr;
            }
        }
        cache.at(bundle).put(smt, compiledExpr);
        compileTime +=
                duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() -
                startTime;
    }
    if (reverse) {
#ifndef DEBUGTEST
        bundle->solver->add(!compiledExpr);
#else
        bundle->solver->add(!compiledExpr, to_string(bundle->assertionCounter++).c_str());
#endif
    } else {
#ifndef DEBUGTEST
        bundle->solver->add(compiledExpr);
#else
        bundle->solver->add(compiledExpr, to_string(bundle->assertionCounter++).c_str());
#endif
    }
}

void Z3Manager::putSolverBundle(shared_ptr<SolverBundle> &bundle) {
    auto z3Bundle = static_pointer_cast<Z3Bundle>(bundle);
    z3Bundle->solver->pop();
    bundleQ.put(std::move(z3Bundle));
}

void Z3Manager::addFalseExpr(const shared_ptr<SolverBundle> &bundle) {
    auto z3Bundle = static_pointer_cast<Z3Bundle>(bundle);
    z3Bundle->solver->add(z3Bundle->z3ctx->bool_val(false));
}

void Z3Manager::addTrueExpr(const shared_ptr<SolverBundle> &bundle) {
    auto z3Bundle = static_pointer_cast<Z3Bundle>(bundle);
    z3Bundle->solver->add(z3Bundle->z3ctx->bool_val(true));
}

SolverCheckResult Z3Manager::checkSolver(const shared_ptr<SolverBundle> &bundle) {
    auto z3Bundle = static_pointer_cast<Z3Bundle>(bundle);
    auto startTime = duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    auto ret = z3Bundle->solver->check();
    auto timeUsed =
            duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() -
            startTime;
    solveTime += timeUsed;
    solveCount++;
    if (timeUsed > maxSolveTime) {
        maxSolveTime = timeUsed;
    }
    // Note this implies the defination of z3::check_result and SolverCheckResult are exactly same
    return static_cast<SolverCheckResult>(ret);
}

string Z3Manager::dumpSMT2(const shared_ptr<SolverBundle> &bundle) {
    auto z3Bundle = static_pointer_cast<Z3Bundle>(bundle);
    return z3Bundle->solver->to_smt2();
}

string Z3Manager::dumpModel(const shared_ptr<SolverBundle> &bundle) {
    auto z3Bundle = static_pointer_cast<Z3Bundle>(bundle);
    return z3Bundle->solver->get_model().to_string();
}

Z3Bundle::Z3Bundle() {
    z3ctx = std::make_unique<z3::context>();
    solver = std::make_unique<z3::solver>(*z3ctx);
    Z3_param_descrs solver_params = Z3_solver_get_param_descrs(*z3ctx, *solver);
    Z3_param_descrs_inc_ref(*z3ctx, solver_params);
    z3::params params(*z3ctx);
    if (Global::solverTimeout > 0) {
        params.set(":timeout", Global::solverTimeout);
    }
//    params.set(":threads", (unsigned) SCD_THREADS);
    Z3_params_validate(*z3ctx, params, solver_params);
    solver->set(params);
    Z3_param_descrs_dec_ref(*z3ctx, solver_params);
}
