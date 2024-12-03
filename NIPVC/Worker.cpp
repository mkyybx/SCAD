#include "Worker.h"
#include "ProgressPrinter.h"
#include "GlobalVariables.h"

using namespace std;
using namespace SCDetector;

Worker::Worker(const string &name) : name(name) {
    ProgressPrinter::getPrinter()->addKey("Worker " + name, &workingCount, &Global::numOfThreads);
}

Worker::~Worker() {
    ProgressPrinter::getPrinter()->removeKey("Worker " + name);
}
