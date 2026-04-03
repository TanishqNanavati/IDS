#include "include/common.h"
#include "include/parser.h"
#include "include/net_reader.h"
#include "include/rate.h"
#include "include/rule_engine.h"
#include "include/anomaly.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

static volatile int running = 1;

void handle_sigint(int sig)
{
    (void)sig;
    running = 0;
}

int main(int argc, char *argv[])
{
    LogLevel log_level = INFO;
    int interval = 3;

    if(argc > 1){
        int level = atoi(argv[1]);
        if(level >= DEBUG && level <= ERROR)
            log_level = (LogLevel)level;
    }

    if(argc > 2){
        interval = atoi(argv[2]);
        if(interval <= 0) interval = 3;
    }

    signal(SIGINT, handle_sigint);
    log_init(log_level);

    log_info("Starting Network IDS (Phase 4 - Anomaly Detection)");
    log_info("Sampling interval: %d seconds", interval);

    /* -------- create timestamped log file -------- */
    char filename[256];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    strftime(filename,sizeof(filename),
             "../ids_output_%Y%m%d_%H%M%S.log", tm_info);

    FILE *fp = fopen(filename,"a");
    if(!fp){
        log_error("Failed to open output file");
        return EXIT_FAILURE;
    }

    log_info("Logging to file: %s", filename);

    /* -------- Rule Engine -------- */
    RuleEngine *engine = rule_engine_create(10);

    rule_engine_add_rule(engine,
        "HIGH_RX_TRAFFIC",
        "High incoming traffic",
        SEVERITY_WARN,
        METRIC_RX_BYTES_PER_SEC,
        1000000);

    rule_engine_add_rule(engine,
        "HIGH_TX_TRAFFIC",
        "High outgoing traffic",
        SEVERITY_WARN,
        METRIC_TX_BYTES_PER_SEC,
        1000000);

    rule_engine_add_rule(engine,
        "RX_ERRORS",
        "Receive errors detected",
        SEVERITY_CRITICAL,
        METRIC_RX_ERRORS_PER_SEC,
        10);

    /* -------- Anomaly Detector -------- */
    AnomalyDetector *anomaly = anomaly_create(8);

    Network_Snapshot *prev_snapshot = NULL;
    int iteration = 0;

    while(running)
    {
        iteration++;

        Network_Snapshot *curr_snapshot = read_snapshot();
        if(!curr_snapshot){
            log_error("Failed to read network snapshot");
            sleep(interval);
            continue;
        }

        if(log_level <= INFO){
            printf("\n[Iteration %d]\n", iteration);
            print_snapshot(curr_snapshot);
        }

        if(prev_snapshot)
        {
            RateSnapShot *rate_snap =
                calculate_rates(prev_snapshot,curr_snapshot,(double)interval);

            if(rate_snap)
            {
                /* ---- print rates ---- */
                if(log_level <= INFO)
                    print_rate_snapshot(rate_snap);

                /* ---- Rule Engine ---- */
                AlertList *alerts =
                    rule_engine_evaluate(engine,rate_snap);

                if(alerts){
                    print_alerts(alerts);
                    log_alerts(fp,alerts);
                    alert_list_destroy(alerts);
                }

                /* ---- Anomaly Detection ---- */
                AlertList *anom =
                    anomaly_evaluate(anomaly,rate_snap);

                if(anom){
                    print_alerts(anom);
                    log_alerts(fp,anom);
                    alert_list_destroy(anom);
                }

                /* ---- log rates ---- */
                log_rate_snapshot(fp,rate_snap);
                fflush(fp);

                destroy_rate_snapshot(rate_snap);
            }
        }
        else
        {
            log_info("First iteration — collecting baseline");
        }

        if(prev_snapshot)
            destroy_snapshot(prev_snapshot);

        prev_snapshot = curr_snapshot;

        if(running)
            sleep(interval);
    }

    /* -------- cleanup -------- */
    if(prev_snapshot)
        destroy_snapshot(prev_snapshot);

    anomaly_destroy(anomaly);
    rule_engine_destroy(engine);

    fprintf(fp,"\n===== IDS Shutdown =====\n");
    fclose(fp);

    log_info("Shutdown complete");
    return EXIT_SUCCESS;
}