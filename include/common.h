// For logging utilities 

#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<stdarg.h>

// levels of logs

typedef enum{
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3
}log;

extern log global_log;    // to keep track of global logging

void log_init(log l);     // initializing logger function

void log_msg(log l,const char* fmt,...);     // to log message along with timestamp


#define log_debug(fmt,...) log_msg(DEBUG,fmt,##__VA_ARGS__)
#define log_info(fmt,...) log_msg(INFO,fmt,##__VA_ARGS__)
#define log_warn(fmt,...) log_msg(WARN,fmt,##__VA_ARGS__)
#define log_error(fmt,...) log_msg(ERROR,fmt,##__VA_ARGS__)


// network interface statistics

typedef struct{

    char interface[16];   // eth0,lo,wlan0     
    // recv --> received
    // tr   --> transmitted
    unsigned long recv_bytes;
    unsigned long recv_pkts;
    unsigned long recv_errors;
    unsigned long recv_dropped;
    unsigned long tr_bytes;
    unsigned long tr_pkts;
    unsigned long tr_errors;
    unsigned long tr_dropped;
}NetStats;

typedef struct{

    NetStats *interfaces;      // pointer to array of interfaces
    int count;                 // No of interfaces
    time_t timestamp;          // defines the time when particular snapshot is taken

}Network_Snapshot;

Network_Snapshot *create_snapshot(void);
void destroy_snapshot(Network_Snapshot *snap);

#endif