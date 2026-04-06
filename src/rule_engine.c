#include "rule_engine.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

RuleEngine *rule_engine_create(int max_rules)
{
    (void)max_rules;
    RuleEngine *e = malloc(sizeof(RuleEngine));
    return e;
}

void rule_engine_destroy(RuleEngine *engine)
{
    if(engine) free(engine);
}

/* classification */
const char* classify_attack(const RateStats *r)
{
    if(r->recv_pkts_per_sec > 5000)
        return "DoS Attack";

    if(r->recv_pkts_per_sec > 2000 &&
       r->recv_bytes_per_sec < 200000)
        return "Port Scan";

    if(r->recv_bytes_per_sec > 5000000)
        return "Data Exfiltration";

    return "Normal";
}

AlertList *rule_engine_evaluate(RuleEngine *engine,
                                const RateSnapShot *rates)
{
    (void)engine;
    if(!rates) return NULL;

    AlertList *alerts = alert_list_create(8);
    if(!alerts) return NULL;

    for(int i=0;i<rates->count;i++)
    {
        const RateStats *r = &rates->interfaces[i];

        printf("Interface: %s | Attack: %s\n",
               r->interface, classify_attack(r));

        /* DoS detection */
        if(r->recv_pkts_per_sec > 5000)
        {
            Alert a;

            strncpy(a.interface,r->interface,15);
            strcpy(a.rule_name,"DOS_PACKET_FLOOD");
            a.severity = SEVERITY_CRITICAL;
            a.value = r->recv_pkts_per_sec;
            a.threshold = 5000;
            a.timestamp = time(NULL);

            snprintf(a.message,sizeof(a.message),
                     "DoS suspected %.2f pps",
                     r->recv_pkts_per_sec);

            alert_list_add(alerts,&a);
        }

        /* Port scan detection */
        if(r->recv_pkts_per_sec > 2000 &&
           r->recv_bytes_per_sec < 200000)
        {
            Alert a;

            strncpy(a.interface,r->interface,15);
            strcpy(a.rule_name,"PORT_SCAN");
            a.severity = SEVERITY_WARN;
            a.value = r->recv_pkts_per_sec;
            a.threshold = 2000;
            a.timestamp = time(NULL);

            strcpy(a.message,"Port scan suspected");

            alert_list_add(alerts,&a);
        }

        /* bandwidth spike */
        if(r->recv_bytes_per_sec > 5000000)
        {
            Alert a;

            strncpy(a.interface,r->interface,15);
            strcpy(a.rule_name,"HIGH_BANDWIDTH");
            a.severity = SEVERITY_WARN;
            a.value = r->recv_bytes_per_sec;
            a.threshold = 5000000;
            a.timestamp = time(NULL);

            strcpy(a.message,"High bandwidth usage");

            alert_list_add(alerts,&a);
        }
    }

    return alerts;
}

/* ================= ALERT LIST ================= */

AlertList *alert_list_create(int capacity)
{
    AlertList *list = malloc(sizeof(AlertList));
    if(!list) return NULL;

    list->alerts = malloc(sizeof(Alert) * capacity);
    if(!list->alerts){
        free(list);
        return NULL;
    }

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

    if(list->count >= list->capacity)
    {
        int newcap = list->capacity * 2;
        Alert *tmp = realloc(list->alerts,sizeof(Alert)*newcap);
        if(!tmp) return -1;

        list->alerts = tmp;
        list->capacity = newcap;
    }

    list->alerts[list->count++] = *alert;
    return 0;
}

/* ================= PRINT ALERTS ================= */

const char *severity_to_string(AlertSeverity s)
{
    switch(s){
        case SEVERITY_INFO: return "INFO";
        case SEVERITY_WARN: return "WARN";
        case SEVERITY_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

void print_alerts(const AlertList *list)
{
    if(!list || list->count == 0)
    {
        printf("✓ No alerts triggered\n");
        return;
    }

    for(int i=0;i<list->count;i++)
    {
        const Alert *a = &list->alerts[i];

        printf("\n[%s] %s | %s\n",
               severity_to_string(a->severity),
               a->interface,
               a->rule_name);

        printf("    %s\n", a->message);
        printf("    value=%.2f threshold=%.2f\n",
               a->value,a->threshold);
    }
}