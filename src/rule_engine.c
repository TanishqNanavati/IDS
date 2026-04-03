#include "rule_engine.h"
#include <string.h>

/* ===========================
   Helper Functions
   =========================== */

const char *severity_to_string(AlertSeverity severity)
{
    switch(severity) {
        case SEVERITY_INFO: return "INFO";
        case SEVERITY_WARN: return "WARN";
        case SEVERITY_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

const char *metric_type_to_string(MetricType type)
{
    switch(type) {
        case METRIC_RX_BYTES_PER_SEC: return "RX Bytes/sec";
        case METRIC_TX_BYTES_PER_SEC: return "TX Bytes/sec";
        case METRIC_RX_PKTS_PER_SEC: return "RX Packets/sec";
        case METRIC_TX_PKTS_PER_SEC: return "TX Packets/sec";
        case METRIC_RX_ERRORS_PER_SEC: return "RX Errors/sec";
        case METRIC_TX_ERRORS_PER_SEC: return "TX Errors/sec";
        case METRIC_RX_DROPPED_PER_SEC: return "RX Dropped/sec";
        case METRIC_TX_DROPPED_PER_SEC: return "TX Dropped/sec";
        default: return "UNKNOWN";
    }
}

static double get_metric_value(const RateStats *rate, MetricType type)
{
    switch(type) {
        case METRIC_RX_BYTES_PER_SEC: return rate->recv_bytes_per_sec;
        case METRIC_TX_BYTES_PER_SEC: return rate->tr_bytes_per_sec;
        case METRIC_RX_PKTS_PER_SEC: return rate->recv_pkts_per_sec;
        case METRIC_TX_PKTS_PER_SEC: return rate->tr_pkts_per_sec;
        case METRIC_RX_ERRORS_PER_SEC: return rate->recv_errors_per_sec;
        case METRIC_TX_ERRORS_PER_SEC: return rate->tr_errors_per_sec;
        case METRIC_RX_DROPPED_PER_SEC: return rate->recv_dropped_per_sec;
        case METRIC_TX_DROPPED_PER_SEC: return rate->tr_dropped_per_sec;
        default: return 0.0;
    }
}

/* ===========================
   Rule Engine API
   =========================== */

RuleEngine *rule_engine_create(int max_rules)
{
    if (max_rules <= 0) return NULL;

    RuleEngine *engine = malloc(sizeof(RuleEngine));
    if (!engine) return NULL;

    engine->rules = calloc(max_rules, sizeof(Rule));
    if (!engine->rules) {
        free(engine);
        return NULL;
    }

    engine->rule_count = 0;
    engine->max_rules = max_rules;
    return engine;
}

void rule_engine_destroy(RuleEngine *engine)
{
    if (!engine) return;
    free(engine->rules);
    free(engine);
}

int rule_engine_add_rule(RuleEngine *engine,
                         const char *name,
                         const char *description,
                         AlertSeverity severity,
                         MetricType metric_type,
                         double threshold)
{
    if (!engine || !name) return -1;

    if (engine->rule_count >= engine->max_rules)
        return -1;

    Rule *rule = &engine->rules[engine->rule_count];

    strncpy(rule->name, name, sizeof(rule->name)-1);
    strncpy(rule->description, description, sizeof(rule->description)-1);

    rule->severity = severity;
    rule->metric_type = metric_type;
    rule->threshold = threshold;
    rule->enabled = 1;

    engine->rule_count++;
    return 0;
}

int rule_engine_enable_rule(RuleEngine *engine, const char *name, int enabled)
{
    if (!engine || !name) return -1;

    for (int i=0;i<engine->rule_count;i++){
        if(strcmp(engine->rules[i].name,name)==0){
            engine->rules[i].enabled = enabled;
            return 0;
        }
    }
    return -1;
}

AlertList *rule_engine_evaluate(RuleEngine *engine, const RateSnapShot *rates)
{
    if (!engine || !rates) return NULL;

    AlertList *alerts = alert_list_create(16);
    if (!alerts) return NULL;

    for(int r=0;r<engine->rule_count;r++){
        Rule *rule = &engine->rules[r];
        if(!rule->enabled) continue;

        for(int i=0;i<rates->count;i++){
            const RateStats *rate = &rates->interfaces[i];

            double value = get_metric_value(rate, rule->metric_type);

            if(value > rule->threshold){
                Alert alert;

                strncpy(alert.interface, rate->interface, sizeof(alert.interface)-1);
                strncpy(alert.rule_name, rule->name, sizeof(alert.rule_name)-1);

                alert.severity = rule->severity;
                alert.value = value;
                alert.threshold = rule->threshold;
                alert.timestamp = time(NULL);

                snprintf(alert.message,sizeof(alert.message),
                         "%s exceeded on %s: %.2f > %.2f",
                         rule->name, alert.interface, value, rule->threshold);

                alert_list_add(alerts,&alert);
            }
        }
    }

    return alerts;
}

/* ===========================
   Alert List
   =========================== */

AlertList *alert_list_create(int capacity)
{
    AlertList *list = malloc(sizeof(AlertList));
    if(!list) return NULL;

    list->alerts = calloc(capacity,sizeof(Alert));
    list->count = 0;
    list->capacity = capacity;
    return list;
}

void alert_list_destroy(AlertList *list)
{
    if(!list) return;
    free(list->alerts);
    free(list);
}

int alert_list_add(AlertList *list, const Alert *alert)
{
    if(!list || !alert) return -1;

    if(list->count >= list->capacity){
        int newcap = list->capacity * 2;
        Alert *tmp = realloc(list->alerts,newcap*sizeof(Alert));
        if(!tmp) return -1;

        list->alerts = tmp;
        list->capacity = newcap;
    }

    list->alerts[list->count++] = *alert;
    return 0;
}

void print_alerts(const AlertList *list)
{
    if(!list || list->count == 0){
        printf("✓ No alerts triggered\n");
        return;
    }

    printf("\n=========== ALERTS ===========\n");

    for(int i=0;i<list->count;i++){
        const Alert *a = &list->alerts[i];

        printf("[%d] %s | %s | %.2f > %.2f\n",
               i+1,
               severity_to_string(a->severity),
               a->interface,
               a->value,
               a->threshold);

        printf("    %s\n", a->message);
    }

    printf("==============================\n");
}

void log_alerts(FILE *fp, const AlertList *list)
{
    if(!fp || !list) return;

    for(int i=0;i<list->count;i++){
        const Alert *a = &list->alerts[i];

        fprintf(fp,"[%s] %s %s %.2f > %.2f\n",
                severity_to_string(a->severity),
                a->rule_name,
                a->interface,
                a->value,
                a->threshold);
    }
}