#include "YicesManager.h"

namespace SCDetector {
    YicesBundle::YicesBundle() {
        ctx = yices_new_context(nullptr);
    }

    YicesBundle::~YicesBundle() {
        yices_free_context(ctx);
    }

    YicesManager::YicesManager(uint64_t lruCacheSize) {
        for (auto i = 0; i < SCD_THREADS; i++) {
            shared_ptr<YicesBundle> bundle;
            bundle.reset(new YicesBundle());
            // Init cache to avoid race condition
            cache.insert(pair(bundle, LRUCache<string, term_t>(lruCacheSize)));
            // Init Q
            bundleQ.put(std::move(bundle));
        }
    }

    std::shared_ptr<YicesBundle> getSolverBundle() {
        return bundle;
    }

    void addSMT(const std::shared_ptr<YicesBundle> &bundle, const std::string &smt, bool reverse) {
        term_t expr = yices_parse_term(smt.c_str());
        assert(expr != NULL_TERM);
        if (reverse) {
            expr = yices_not(expr);
        }
        int32_t code = yices_assert_formula(bundle->ctx, expr);
        assert(code == 0);
    }

    void addFalseExpr(const std::shared_ptr<YicesBundle> &bundle) {
        int32_t code = yices_assert_formula(bundle->ctx, bundle->boolFalse);
        assert(code == 0);
    }

    void addTrueExpr(const std::shared_ptr<YicesBundle> &bundle) {
        int32_t code = yices_assert_formula(bundle->ctx, bundle->boolTrue);
        assert(code == 0);
    }

    int32_t checkSolver(const std::shared_ptr<YicesBundle> &bundle) {
        smt_status_t ret = yices_check_context(bundle->ctx, NULL);
        assert(ret != STATUS_ERROR);
        return static_cast<int32_t>(ret);
    }

    std::string dumpModel(const std::shared_ptr<YicesBundle> &bundle) {
        model_t *model = yices_get_model(bundle->ctx, true);
        assert(model != NULL);
        char *str = yices_model_to_string(model, 120, 1, 0);
        std::string ret = str;
        yices_free_string(str);
        yices_free_model(model);
        return ret;
    }


    int main() {
        yices_init();
        YicesManager mgr;
        std::shared_ptr<YicesBundle> bundle = mgr.getSolverBundle();
        mgr.addSMT(bundle, "(and true false)", false);
        int32_t status = mgr.checkSolver(bundle);
        std::string model = mgr.dumpModel(bundle);
        yices_exit();
        return 0;
    }

} // SCDetector