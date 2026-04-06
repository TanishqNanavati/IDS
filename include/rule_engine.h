// Rule Engine - Detect anomalies based on thresholds
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

/* Alert structure */
typedef struct {
    char interface[16];
    AlertSeverity severity;
    char rule_name[64];
    char message[256];
    double value;           /* Actual measured value */
    double threshold;       /* Rule threshold */
    time_t timestamp;
} Alert;

/* Alert list */
typedef struct {
    Alert *alerts;
    int count;
    int capacity;
} AlertList;

/* Rule metric types */
typedef enum {
    METRIC_RX_BYTES_PER_SEC = 0,
    METRIC_TX_BYTES_PER_SEC = 1,
    METRIC_RX_PKTS_PER_SEC = 2,
    METRIC_TX_PKTS_PER_SEC = 3,
    METRIC_RX_ERRORS_PER_SEC = 4,
    METRIC_TX_ERRORS_PER_SEC = 5,
    METRIC_RX_DROPPED_PER_SEC = 6,
    METRIC_TX_DROPPED_PER_SEC = 7
} MetricType;

/* Rule structure */
typedef struct {
    char name[64];
    char description[256];
    AlertSeverity severity;
    MetricType metric_type;
    double threshold;       /* Alert if metric > threshold */
    int enabled;            /* 1 = enabled, 0 = disabled */
} Rule;

/* Rule Engine context */
typedef struct {
    Rule *rules;
    int rule_count;
    int max_rules;
} RuleEngine;

/**
 * Create and initialize rule engine
 */
RuleEngine *rule_engine_create(int max_rules);

/**
 * Destroy rule engine
 */
void rule_engine_destroy(RuleEngine *engine);

/**
 * Add a rule to the engine
 * Returns 0 on success, -1 on failure
 */
int rule_engine_add_rule(RuleEngine *engine,
                         const char *name,
                         const char *description,
                         AlertSeverity severity,
                         MetricType metric_type,
                         double threshold);

/**
 * Enable/disable a rule by name
 * Returns 0 on success, -1 if rule not found
 */
int rule_engine_enable_rule(RuleEngine *engine, const char *name, int enabled);

/**
 * Evaluate all rules against rate snapshot
 * Returns AlertList with triggered alerts
 * Caller must free with alert_list_destroy()
 */
AlertList *rule_engine_evaluate(RuleEngine *engine, const RateSnapShot *rates);

/**
 * Create empty alert list
 */
AlertList *alert_list_create(int capacity);

/**
 * Destroy alert list
 */
void alert_list_destroy(AlertList *list);

/**
 * Add alert to list
 */
int alert_list_add(AlertList *list, const Alert *alert);

/**
 * Print alerts to stdout
 */
void print_alerts(const AlertList *list);

/**
 * Log alerts to file
 */
void log_alerts(FILE *fp, const AlertList *list);

/**
 * Get severity string
 */
const char *severity_to_string(AlertSeverity severity);

/**
 * Get metric type string
 */
const char *metric_type_to_string(MetricType type);

#endif