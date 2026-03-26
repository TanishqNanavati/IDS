#ifndef RATE_H
#define RATE_H


#include"common.h"


typedef struct{

    char interface[16];

    // bytes per sec
    double recv_bytes_per_sec;
    double tr_bytes_per_sec;

    // pkts per sec
    double recv_pkts_per_sec;
    double tr_pkts_per_sec; 

    // error rates
    double recv_errors_per_sec;
    double tr_errors_per_sec;

    // dropped rates
    double recv_dropped_per_sec;
    double tr_dropped_per_sec;

    // Raw counts (for reference) 
    unsigned long recv_bytes;
    unsigned long recv_pkts;
    unsigned long tr_bytes;
    unsigned long tr_pkts;

}RateStats;

typedef struct{
    RateStats *interfaces;
    int count;
    time_t timestamp;
    double time_delta;              // seconds since last snapshot
}RateSnapShot;

RateSnapShot *calculate_rates(const Network_Snapshot *prev,const Network_Snapshot *curr,double time_delta);
RateSnapShot *create_rate_snapshot(void);
void destroy_rate_snapshot(RateSnapShot *snap);
void print_rate_snapshot(const RateSnapShot *snap);
void log_rate_snapshot(FILE *fp,const RateSnapShot *snap);

#endif