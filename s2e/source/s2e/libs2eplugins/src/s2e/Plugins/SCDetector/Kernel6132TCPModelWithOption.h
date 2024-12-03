#ifndef SRC_KERNEL6132TCPMODELWITHOPTION_H
#define SRC_KERNEL6132TCPMODELWITHOPTION_H

#include "Kernel6132TCPModel.h"

class Kernel6132TCPModelWithOption : public Kernel6132TCPModel {
public:
    explicit Kernel6132TCPModelWithOption(s2e::plugins::Propagator *scd);
};


#endif //SRC_KERNEL6132TCPMODELWITHOPTION_H
