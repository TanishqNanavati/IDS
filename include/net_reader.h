// API for reading network packets

#ifndef NET_READER_H
#define NET_READER_H

#include "common.h"


// to read real time network network packets from /proc/net/dev
Network_Snapshot *read_snapshot(void);

// to read test data of network statistics from file
Network_Snapshot *read_file(const char* filepath); 

#endif