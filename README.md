anomaly.h:
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

AlertList *anomaly_evaluate(AnomalyDetector *detector,const RateSnapShot *rates);

#endif

common.h:
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

net_reader.h:
// API for reading network packets

#ifndef NET_READER_H
#define NET_READER_H

#include "common.h"


// to read real time network network packets from /proc/net/dev
Network_Snapshot *read_snapshot(void);

// to read test data of network statistics from file
Network_Snapshot *read_file(const char* filepath); 

#endif

parser.h:
// to parse network stats from /proc/net/dev to network statistics

#ifndef PARSER_H
#define PARSER_H

#include "common.h"

// to parse a single line from /proc/net/dev
// returns --> 0 on success or -1 on error

int parse_line(const char *line,NetStats *out);

// to parse the entire file /proc/net/dev content

Network_Snapshot* parse_file(const char* content);


// utility function to print network snapshot

void print_snapshot(const Network_Snapshot* snap);

#endif

rate.h:
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

rule_engine.h:
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

anomaly.c:
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

common.c:
#include "common.h"

LogLevel global_log = INFO;

static const char* log_str(LogLevel l)
{
    switch(l){
        case DEBUG: return "DEBUG";
        case INFO:  return "INFO";
        case WARN:  return "WARN";
        case ERROR: return "ERROR";
        default:    return "UNKNOWN";
    }
}

void log_init(LogLevel l)
{
    global_log = l;
}

void log_msg(LogLevel l, const char* fmt, ...)
{
    if(l < global_log) return;

    time_t now = time(NULL);
    struct tm* timeinfo = localtime(&now);

    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

    fprintf(stderr, "[%s] [%-5s] ", timestamp, log_str(l));

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
}

Network_Snapshot *create_snapshot(void)
{
    Network_Snapshot* snap = malloc(sizeof(Network_Snapshot));
    if(!snap){
        log_error("Failed to allocate Network_Snapshot");
        return NULL;
    }
    snap->interfaces = NULL;
    snap->count = 0;
    snap->timestamp = time(NULL);
    return snap;
}

void destroy_snapshot(Network_Snapshot* snap)
{
    if(!snap) return;
    free(snap->interfaces);
    free(snap);
}

net_reader.c:
#include"net_reader.h"
#include<stdio.h>

static char* readfile(const char *filepath){
    FILE *f = fopen(filepath,"r");
    if(!f){
        log_error("Failed to open the file : %s",filepath);
        return NULL;
    }

    size_t buffer_size = 4096;
    size_t total_read = 0;
    char *buff = (char *)malloc(buffer_size);

    if(!buff){
        log_error("Failed to allocate buffer for file: %s", filepath);
        fclose(f);
        return NULL;
    }

    while(1){
        size_t bytes_read = fread(buff + total_read,1,buffer_size-total_read-1,f);
        if(!bytes_read) break;

        total_read += bytes_read;

        if(total_read >= buffer_size - 1){
            buffer_size *= 2;
            char *new_buff = (char *)realloc(buff,buffer_size);

            if(!new_buff){
                log_error("Failed to expand buffer file : %s",filepath);
                free(buff);
                fclose(f);
                return NULL;
            }

            buff = new_buff;
        }
    }

    fclose(f);

    if(!total_read){
        log_error("No data read from file: %s", filepath);
        free(buff);
        return NULL;
    }

    buff[total_read] = '\0';
    log_debug("Read %zu bytes from %s", total_read, filepath);
    return buff;
}

Network_Snapshot *read_snapshot(void){
    return read_file("/proc/net/dev");
}

Network_Snapshot* read_file(const char *filepath){
    if(!filepath){
        log_error("file path cannot be NULL");
        return NULL;
    }

    char *content = readfile(filepath);
    if(!content) return NULL;

    log_debug("Read %zu bytes from %s", strlen(content), filepath);

    extern Network_Snapshot *parse_file(const char *content);
    Network_Snapshot *snap = parse_file(content);

    free(content);
    return snap; 
}

parser.c:
#include "parser.h"
#include <ctype.h>

/**
 * Parse a single line from /proc/net/dev
 */
int parse_line(const char *line, NetStats *out){
    if(!line || !out){
        log_error("Invalid input to parse_line");
        return -1;
    }

    memset(out, 0, sizeof(NetStats));

                
    while (isspace((unsigned char)*line)) line++;

    if(!line[0]) return -1;

    /* Skip header lines */
    if(strchr(line,'|')) return -1;

    const char *colon = strchr(line, ':');
    if(!colon){
        return -1;
    }

    int name_len = colon - line;

    if(name_len <= 0 || (size_t)name_len >= sizeof(out->interface)){
        log_warn("Invalid interface name length: %d", name_len);
        return -1;
    }

    memcpy(out->interface, line, name_len);
    out->interface[name_len] = '\0';

    unsigned long rx_fifo, rx_frame, rx_compressed, rx_multicast;
    unsigned long tx_fifo, tx_colls, tx_carrier, tx_compressed;

    int ret = sscanf(colon + 1,
                     "%lu %lu %lu %lu %lu %lu %lu %lu "
                     "%lu %lu %lu %lu %lu %lu %lu %lu",
                     &out->recv_bytes,
                     &out->recv_pkts,
                     &out->recv_errors,
                     &out->recv_dropped,
                     &rx_fifo,
                     &rx_frame,
                     &rx_compressed,
                     &rx_multicast,
                     &out->tr_bytes,
                     &out->tr_pkts,
                     &out->tr_errors,
                     &out->tr_dropped,
                     &tx_fifo,
                     &tx_colls,
                     &tx_carrier,
                     &tx_compressed
    );

    if(ret != 16){
        log_error("Failed to parse line: %s", line);
        return -1;
    }

    log_debug("Parsed interface: %s RX:%lu TX:%lu",
              out->interface,
              out->recv_pkts,
              out->tr_pkts);

    return 0;
}


Network_Snapshot* parse_file(const char* content){
    if(!content){
        log_error("Content to parse cannot be NULL");
        return NULL;
    }

    Network_Snapshot *snap = create_snapshot();
    if(!snap) return NULL;

    int max_interfaces = 32;
    snap->interfaces = calloc(max_interfaces, sizeof(NetStats));

    if(!snap->interfaces){
        log_error("Failed to allocate interfaces array");
        destroy_snapshot(snap);
        return NULL;
    }

    int count = 0;
    const char *line_start = content;

    for (const char *p = content; *p; p++) {
        if (*p == '\n') {

            int line_len = p - line_start;

            if (line_len > 0) {
                char line_buf[256];

                if (line_len >= (int)sizeof(line_buf)) {
                    log_warn("Line too long, skipping");
                    line_start = p + 1;
                    continue;
                }

                memcpy(line_buf, line_start, line_len);
                line_buf[line_len] = '\0';

                /* CHECK LIMIT BEFORE WRITING */
                if (count >= max_interfaces) {
                    log_warn("Too many interfaces, capping at %d", max_interfaces);
                    break;
                }

                if (parse_line(line_buf, &snap->interfaces[count]) == 0) {
                    count++;
                }
            }

            line_start = p + 1;
        }
    }

    snap->count = count;
    log_info("Parsed %d network interfaces", count);

    return snap;
}


void print_snapshot(const Network_Snapshot* snap){
    if (!snap) {
        printf("Error: NULL snapshot\n");
        return;
    }

    printf("\n");
    printf("====================================\n");
    printf("Network Interfaces (%d total)\n", snap->count);
    printf("====================================\n");

    for (int i = 0; i < snap->count; i++) {
        const NetStats *stats = &snap->interfaces[i];

        printf("\n[%d] Interface: %s\n", i + 1, stats->interface);
        printf("    RX Bytes:    %lu\n", stats->recv_bytes);
        printf("    RX Packets:  %lu\n", stats->recv_pkts);
        printf("    RX Errors:   %lu\n", stats->recv_errors);
        printf("    RX Dropped:  %lu\n", stats->recv_dropped);
        printf("    TX Bytes:    %lu\n", stats->tr_bytes);
        printf("    TX Packets:  %lu\n", stats->tr_pkts);
        printf("    TX Errors:   %lu\n", stats->tr_errors);
        printf("    TX Dropped:  %lu\n", stats->tr_dropped);
    }

    printf("\n====================================\n");
    printf("End of Report\n");
    printf("====================================\n\n");
}

rate.c:
#include"rate.h"
#include<math.h>

static inline double calculate_rate(unsigned long prev,unsigned long curr,double time_delta){
    if(time_delta <= 0) return 0.0;
    long delta = (long)(curr - prev);
    if(delta < 0){
        log_warn("Counter wraparound detected: %lu -> %lu", prev, curr);
        return 0.0;
    }
    return (double)delta / time_delta;
}

static int find_interface(const Network_Snapshot *snap,const char *name){
    if(!snap || !name) return -1;
    for(int i=0;i<snap->count;i++)
        if(strcmp(snap->interfaces[i].interface,name) == 0)
            return i;
    return -1;
}

static void print_rate_graph(double value)
{
    double kb = value / 1024.0;
    int bars = kb * 2;   // more sensitive

    if(bars < 1 && value > 0) bars = 1;
    if(bars > 50) bars = 50;

    printf("[");
    for(int i=0;i<bars;i++) printf("#");
    for(int i=bars;i<50;i++) printf(" ");
    printf("]");
}
/* ---------- NEW helper ---------- */
static char *format_bytes(double bytes, char *buf, size_t size)
{
    const char *units[] = {"B/s","KB/s","MB/s","GB/s"};
    int unit = 0;

    while(bytes > 1024 && unit < 3){
        bytes /= 1024;
        unit++;
    }

    snprintf(buf,size,"%.2f %s",bytes,units[unit]);
    return buf;
}
/* -------------------------------- */

RateSnapShot *create_rate_snapshot(void){
    RateSnapShot *snap = malloc(sizeof(RateSnapShot));
    if (!snap) {
        log_error("Failed to allocate RateSnapshot");
        return NULL;
    }

    snap->interfaces = NULL;
    snap->count = 0;
    snap->timestamp = time(NULL);
    snap->time_delta = 0.0;
    return snap;
}

RateSnapShot *calculate_rates(const Network_Snapshot *prev,const Network_Snapshot *curr,double time_delta){
    if(!prev || !curr){
        log_error("Previous and current snapshots cannot be NULL");
        return NULL;
    }

    RateSnapShot *rate_snapshot = create_rate_snapshot();
    if(!rate_snapshot) return NULL;

    rate_snapshot->interfaces = calloc(curr->count,sizeof(RateStats));
    if(!rate_snapshot->interfaces){
        destroy_rate_snapshot(rate_snapshot);
        return NULL;
    }

    rate_snapshot->count = curr->count;
    rate_snapshot->time_delta = time_delta;

    for(int i=0;i<curr->count;i++){
        RateStats *rate = &rate_snapshot->interfaces[i];
        const NetStats *curr_stats = &curr->interfaces[i];

        strncpy(rate->interface,curr_stats->interface,sizeof(rate->interface)-1);

        rate->recv_bytes = curr_stats->recv_bytes;
        rate->recv_pkts = curr_stats->recv_pkts;
        rate->tr_bytes = curr_stats->tr_bytes;
        rate->tr_pkts = curr_stats->tr_pkts;

        int prev_idx = find_interface(prev, curr_stats->interface);
        if(prev_idx < 0) continue;

        const NetStats *prev_stats = &prev->interfaces[prev_idx];

        rate->recv_bytes_per_sec =
            calculate_rate(prev_stats->recv_bytes,curr_stats->recv_bytes,time_delta);

        rate->recv_pkts_per_sec =
            calculate_rate(prev_stats->recv_pkts,curr_stats->recv_pkts,time_delta);

        rate->recv_errors_per_sec =
            calculate_rate(prev_stats->recv_errors,curr_stats->recv_errors,time_delta);

        rate->recv_dropped_per_sec =
            calculate_rate(prev_stats->recv_dropped,curr_stats->recv_dropped,time_delta);

        rate->tr_bytes_per_sec =
            calculate_rate(prev_stats->tr_bytes,curr_stats->tr_bytes,time_delta);

        rate->tr_pkts_per_sec =
            calculate_rate(prev_stats->tr_pkts,curr_stats->tr_pkts,time_delta);

        rate->tr_errors_per_sec =
            calculate_rate(prev_stats->tr_errors,curr_stats->tr_errors,time_delta);

        rate->tr_dropped_per_sec =
            calculate_rate(prev_stats->tr_dropped,curr_stats->tr_dropped,time_delta);
    }

    return rate_snapshot;
}

void print_rate_snapshot(const RateSnapShot *snap)
{
    if (!snap) return;

    printf("\n====================================\n");
    printf("Network Rates (%d interfaces, %.1f sec delta)\n",
           snap->count, snap->time_delta);
    printf("====================================\n");

    for (int i = 0; i < snap->count; i++) {
        const RateStats *rate = &snap->interfaces[i];
        char buf[32];

        printf("\n[%d] %s\n", i + 1, rate->interface);
        printf("    RX Bytes:   %s", format_bytes(rate->recv_bytes_per_sec, buf, sizeof(buf)));
        printf("  TX Bytes:   %s\n", format_bytes(rate->tr_bytes_per_sec, buf, sizeof(buf)));

        printf("    RX Pkts: %.2f pps  TX Pkts: %.2f pps\n",
               rate->recv_pkts_per_sec, rate->tr_pkts_per_sec);

        /* Graph inside loop */
        printf("    RX Graph: ");
        print_rate_graph(rate->recv_bytes_per_sec);
        printf("\n");
    }

    printf("\n====================================\n");
}

void log_rate_snapshot(FILE *fp,const RateSnapShot *snap)
{
    if (!fp || !snap) return;

    fprintf(fp,"==== Rates (delta=%.1fs) ====\n",snap->time_delta);

    for(int i=0;i<snap->count;i++){
        const RateStats *rate = &snap->interfaces[i];

        fprintf(fp,
            "%s RX_B/s:%.2f TX_B/s:%.2f "
            "RX_pps:%.2f TX_pps:%.2f "
            "RX_err:%.2f TX_err:%.2f "
            "RX_drp:%.2f TX_drp:%.2f\n",
            rate->interface,
            rate->recv_bytes_per_sec,
            rate->tr_bytes_per_sec,
            rate->recv_pkts_per_sec,
            rate->tr_pkts_per_sec,
            rate->recv_errors_per_sec,
            rate->tr_errors_per_sec,
            rate->recv_dropped_per_sec,
            rate->tr_dropped_per_sec);
    }

    fprintf(fp,"\n");
}

void destroy_rate_snapshot(RateSnapShot *snap)
{
    if(!snap) return;

    if(snap->interfaces){
        free(snap->interfaces);
        snap->interfaces = NULL;
    }

    free(snap);
}

rule_engine.c:
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

main.c:
#include "common.h"
#include "net_reader.h"
#include "rate.h"
#include "rule_engine.h"
#include "anomaly.h"

#include <stdio.h>
#include <unistd.h>
#include <signal.h>

static int running = 1;

void handle_sigint(int sig)
{
    (void)sig;
    running = 0;
}

int main()
{
    signal(SIGINT,handle_sigint);

    int interval = 2;

    Network_Snapshot *prev = NULL;

    RuleEngine *engine = rule_engine_create(16);
    AnomalyDetector *detector = anomaly_create(16);

    while(running)
    {
        Network_Snapshot *curr = read_snapshot();

        if(prev)
        {
            RateSnapShot *rate =
                calculate_rates(prev,curr,interval);

            print_rate_snapshot(rate);

            /* rule alerts */
            AlertList *alerts =
                rule_engine_evaluate(engine,rate);

            if(alerts && alerts->count > 0)
            {
                printf("\n====== RULE ALERTS ======\n");
                print_alerts(alerts);
            }

            alert_list_destroy(alerts);

            /* anomaly alerts */
            AlertList *anom =
                anomaly_evaluate(detector,rate);

            if(anom && anom->count > 0)
            {
                printf("\n===== ANOMALY ALERTS =====\n");
                print_alerts(anom);
            }

            alert_list_destroy(anom);

            destroy_rate_snapshot(rate);
        }

        if(prev) destroy_snapshot(prev);
        prev = curr;

        sleep(interval);
    }

    rule_engine_destroy(engine);
    anomaly_destroy(detector);

    return 0;
}