#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <time.h>
#include "rate.h"
#include "rule_engine.h"

#define MAX_INTERFACES 16
#define MAX_RULES 32
#define HISTOGRAM_BUCKETS 10

typedef struct MetricsServer MetricsServer;

typedef struct {
    char interface[16];
    double rx_bytes_per_sec;
    double tx_bytes_per_sec;
    double rx_pkts_per_sec;
    double tx_pkts_per_sec;
    double rx_errors_per_sec;
    double tx_errors_per_sec;
    double rx_dropped_per_sec;
    double tx_dropped_per_sec;
} InterfaceMetrics;

typedef struct {
    char rule_name[64];
    unsigned long alert_count;
    time_t last_alert;
} RuleMetrics;

typedef struct {
    double buckets[HISTOGRAM_BUCKETS];
    unsigned long total_alerts;
    time_t last_update;
} AlertHistogram;

MetricsServer *metrics_server_create(int port);
void metrics_server_destroy(MetricsServer *server);
void metrics_server_update(MetricsServer *server,
                           unsigned long total_iterations,
                           unsigned long total_alerts,
                           time_t last_update);
void metrics_server_update_interfaces(MetricsServer *server,
                                     const RateSnapShot *rates);
void metrics_server_update_alerts(MetricsServer *server,
                                  const char *rule_name,
                                  time_t alert_time);
char *metrics_server_create_grafana_dashboard_json(MetricsServer *server);

#endif

