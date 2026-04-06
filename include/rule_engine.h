#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include "common.h"
#include "rate.h"

/* Alert severity levels */
typedef enum {
    SEVERITY_INFO = 0,
    SEVERITY_WARN = 1,
    SEVERITY_CRITICAL = 2
} AlertSeverity;

typedef struct {
    char interface[16];
    AlertSeverity severity;
    char rule_name[64];
    char message[256];
    double value;
    double threshold;
    time_t timestamp;
} Alert;

typedef struct {
    Alert *alerts;
    int count;
    int capacity;
} AlertList;

/* simplified rule engine */
typedef struct {
    int dummy;
} RuleEngine;

RuleEngine *rule_engine_create(int max_rules);
void rule_engine_destroy(RuleEngine *engine);

AlertList *rule_engine_evaluate(RuleEngine *engine,
                                const RateSnapShot *rates);

AlertList *alert_list_create(int capacity);
void alert_list_destroy(AlertList *list);
int alert_list_add(AlertList *list, const Alert *alert);

void print_alerts(const AlertList *list);
void log_alerts(FILE *fp, const AlertList *list);

const char *severity_to_string(AlertSeverity severity);
const char* classify_attack(const RateStats *r);

#endif