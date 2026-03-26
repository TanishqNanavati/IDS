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
}LogLevel;

extern LogLevel global_log;

void log_init(LogLevel l);
void log_msg(LogLevel l,const char* fmt,...);

#define log_debug(fmt,...) log_msg(DEBUG,fmt,##__VA_ARGS__)
#define log_info(fmt,...) log_msg(INFO,fmt,##__VA_ARGS__)
#define log_warn(fmt,...) log_msg(WARN,fmt,##__VA_ARGS__)
#define log_error(fmt,...) log_msg(ERROR,fmt,##__VA_ARGS__)

typedef struct{

    char interface[16];
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

    NetStats *interfaces;
    int count;
    time_t timestamp;

}Network_Snapshot;

Network_Snapshot *create_snapshot(void);
void destroy_snapshot(Network_Snapshot *snap);

#endif