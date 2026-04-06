#include "anomaly.h"
#include <math.h>
#include <string.h>

/**
 * Calculate mean of array
 */
static double mean(double *arr, int n)
{
    double sum = 0;
    for(int i = 0; i < n; i++) {
        sum += arr[i];
    }
    return sum / n;
}

/**
 * Calculate standard deviation
 */
static double stddev(double *arr, int n, double m)
{
    double sum = 0;
    for(int i = 0; i < n; i++) {
        double d = arr[i] - m;
        sum += d * d;
    }
    return sqrt(sum / n);
}

/**
 * Create anomaly detector
 */
AnomalyDetector *anomaly_create(int max_interfaces)
{
    AnomalyDetector *detector = malloc(sizeof(AnomalyDetector));
    if(!detector) {
        log_error("Failed to allocate AnomalyDetector");
        return NULL;
    }

    detector->stats = calloc(max_interfaces, sizeof(AnomalyStats));
    if(!detector->stats) {
        log_error("Failed to allocate anomaly stats");
        free(detector);
        return NULL;
    }

    detector->count = max_interfaces;

    log_info("Anomaly detector created for %d interfaces", max_interfaces);
    return detector;
}

/**
 * Destroy anomaly detector
 */
void anomaly_destroy(AnomalyDetector *detector)
{
    if(!detector) return;
    if(detector->stats) {
        free(detector->stats);
    }
    free(detector);
}

/**
 * Get or create stats for interface
 */
static AnomalyStats *get_stats(AnomalyDetector *detector, const char *iface)
{
    if(!detector || !iface) return NULL;

    /* Find existing */
    for(int i = 0; i < detector->count; i++) {
        if(detector->stats[i].interface[0] != '\0' &&
           strcmp(detector->stats[i].interface, iface) == 0) {
            return &detector->stats[i];
        }
    }

    /* Find empty slot */
    for(int i = 0; i < detector->count; i++) {
        if(detector->stats[i].interface[0] == '\0') {
            strncpy(detector->stats[i].interface, iface, sizeof(detector->stats[i].interface) - 1);
            detector->stats[i].index = 0;
            detector->stats[i].filled = 0;
            return &detector->stats[i];
        }
    }

    return NULL;
}

/**
 * Evaluate anomalies using Z-score statistical method
 * 
 * Algorithm:
 *  1. Maintain circular buffer of last 10 RX bandwidth measurements
 *  2. Calculate mean and standard deviation of buffer
 *  3. Calculate Z-score: (current - mean) / stddev
 *  4. If Z-score > 3.0 (3-sigma), flag as anomaly
 */
AlertList *anomaly_evaluate(AnomalyDetector *detector, const RateSnapShot *rates)
{
    if(!detector || !rates) {
        log_error("Invalid parameters to anomaly_evaluate");
        return NULL;
    }

    AlertList *alerts = alert_list_create(16);
    if(!alerts) {
        return NULL;
    }

    /* Evaluate each interface */
    for(int i = 0; i < rates->count; i++) {
        const RateStats *rate = &rates->interfaces[i];
        AnomalyStats *stats = get_stats(detector, rate->interface);

        if(!stats) {
            log_warn("Could not get stats for interface %s", rate->interface);
            continue;
        }

        double current_value = rate->recv_bytes_per_sec;

        /* Add to circular buffer */
        stats->rx_bytes_history[stats->index] = current_value;
        stats->index = (stats->index + 1) % HISTORY_LEN;

        /* Not enough samples yet for statistical analysis */
        if(stats->filled < HISTORY_LEN) {
            stats->filled++;
            log_debug("Interface %s: collecting baseline (%d/%d samples)",
                     rate->interface, stats->filled, HISTORY_LEN);
            continue;
        }

        /* Calculate baseline statistics */
        double m = mean(stats->rx_bytes_history, HISTORY_LEN);
        double sd = stddev(stats->rx_bytes_history, HISTORY_LEN, m);

        /* Avoid division by zero */
        if(sd <= 0.0) {
            log_debug("Interface %s: zero stddev, no anomaly check", rate->interface);
            continue;
        }

        /* Calculate Z-score */
        double z_score = fabs((current_value - m) / sd);

        log_debug("Interface %s: value=%.2f B/s, mean=%.2f, stddev=%.2f, z=%.2f",
                 rate->interface, current_value, m, sd, z_score);

        /* Anomaly if Z-score exceeds threshold (3-sigma = 99.7% confidence) */
        if(z_score > ANOMALY_THRESHOLD) {
            Alert alert;

            strncpy(alert.interface, rate->interface, sizeof(alert.interface) - 1);
            alert.interface[sizeof(alert.interface) - 1] = '\0';

            strncpy(alert.rule_name, "STATISTICAL_ANOMALY", sizeof(alert.rule_name) - 1);
            alert.rule_name[sizeof(alert.rule_name) - 1] = '\0';

            alert.severity = SEVERITY_WARN;
            alert.value = current_value;
            alert.threshold = m;
            alert.timestamp = time(NULL);

            snprintf(alert.message, sizeof(alert.message),
                     "Statistical anomaly detected on %s: %.2f B/s (z-score: %.2f, "
                     "baseline: %.2f ± %.2f B/s)",
                     rate->interface, current_value, z_score, m, sd);

            alert_list_add(alerts, &alert);

            log_warn("ANOMALY: %s", alert.message);
        }
    }

    return alerts;
}