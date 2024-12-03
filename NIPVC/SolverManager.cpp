#include "SolverManager.h"
#include "ProgressPrinter.h"
#include "GlobalVariables.h"

using namespace std;
using namespace SCDetector;

SolverManager::SolverManager() {
    ProgressPrinter::getPrinter()->addKey(LOGNAME_Z3MANAGER_CACHE_MISS_COUNT, &cacheMissCount, &compileCount);
    ProgressPrinter::getPrinter()->addKey(LOGNAME_Z3MANAGER_COMPILE_TIME, &compileTime, &compileTime);
    ProgressPrinter::getPrinter()->addKey(LOGNAME_Z3MANAGER_MAX_SOLVE_TIME, &maxSolveTime, &maxSolveTime);
    ProgressPrinter::getPrinter()->addKey(LOGNAME_Z3MANAGER_SOLVE_RATE, &solveTime, &solveCount);
}
