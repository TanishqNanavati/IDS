#include "anomaly.h"
#include <math.h>
#include <string.h>

static double mean(double *arr, int n)
{
    double s = 0;
    for(int i=0;i<n;i++) s += arr[i];
    return s/n;
}

static double stddev(double *arr, int n, double m)
{
    double s = 0;
    for(int i=0;i<n;i++){
        double d = arr[i] - m;
        s += d*d;
    }
    return sqrt(s/n);
}

AnomalyDetector *anomaly_create(int max_interfaces)
{
    AnomalyDetector *d = malloc(sizeof(AnomalyDetector));
    if(!d) return NULL;

    d->stats = calloc(max_interfaces, sizeof(AnomalyStats));
    d->count = max_interfaces;
    return d;
}

void anomaly_destroy(AnomalyDetector *detector)
{
    if(!detector) return;
    free(detector->stats);
    free(detector);
}

static AnomalyStats *get_stats(AnomalyDetector *d, const char *iface)
{
    for(int i=0;i<d->count;i++){
        if(strcmp(d->stats[i].interface, iface)==0)
            return &d->stats[i];
    }

    for(int i=0;i<d->count;i++){
        if(d->stats[i].interface[0] == '\0'){
            strncpy(d->stats[i].interface, iface, 15);
            return &d->stats[i];
        }
    }

    return NULL;
}

AlertList *anomaly_evaluate(AnomalyDetector *detector,
                            const RateSnapShot *rates)
{
    if(!detector || !rates) return NULL;

    AlertList *alerts = alert_list_create(8);
    if(!alerts) return NULL;

    for(int i=0;i<rates->count;i++){
        const RateStats *r = &rates->interfaces[i];

        AnomalyStats *s = get_stats(detector, r->interface);
        if(!s) continue;

        double value = r->recv_bytes_per_sec;

        /* push into history */
        s->rx_bytes_history[s->index] = value;
        s->index = (s->index + 1) % HISTORY_LEN;

        if(s->filled < HISTORY_LEN){
            s->filled++;
            continue;
        }

        double m = mean(s->rx_bytes_history, HISTORY_LEN);
        double sd = stddev(s->rx_bytes_history, HISTORY_LEN, m);

        if(sd <= 0) continue;

        double z = fabs((value - m) / sd);

        if(z > ANOMALY_THRESHOLD){
            Alert alert;

            strncpy(alert.interface, r->interface, 15);
            strcpy(alert.rule_name, "ANOMALY_RX_SPIKE");

            alert.severity = SEVERITY_WARN;
            alert.value = value;
            alert.threshold = m;
            alert.timestamp = time(NULL);

            snprintf(alert.message,sizeof(alert.message),
                     "Anomaly detected (z=%.2f): %.2f > avg %.2f",
                     z,value,m);

            alert_list_add(alerts,&alert);
        }
    }

    return alerts;
}