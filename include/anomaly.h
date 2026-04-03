#ifndef ANOMALY_H
#define ANOMALY_H

#include "rate.h"
#include "rule_engine.h"

#define HISTORY_LEN 10
#define ANOMALY_THRESHOLD 3.0

typedef struct {
    char interface[16];

    double rx_bytes_history[HISTORY_LEN];
    int index;
    int filled;
} AnomalyStats;

typedef struct {
    AnomalyStats *stats;
    int count;
} AnomalyDetector;

AnomalyDetector *anomaly_create(int max_interfaces);
void anomaly_destroy(AnomalyDetector *detector);

AlertList *anomaly_evaluate(AnomalyDetector *detector,
                            const RateSnapShot *rates);

#endif