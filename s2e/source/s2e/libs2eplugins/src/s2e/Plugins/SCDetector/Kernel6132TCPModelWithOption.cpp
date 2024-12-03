#include "Kernel6132TCPModelWithOption.h"

Kernel6132TCPModelWithOption::Kernel6132TCPModelWithOption(s2e::plugins::Propagator *scd) : Kernel6132TCPModel(scd) {
    tcpHdrSize = 32; // This is the max length of header with max one option. The longest one is SACK which is 10 bytes + 2 bytes padding
}
