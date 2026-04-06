#include "common.h"
#include "net_reader.h"
#include "rate.h"
#include "rule_engine.h"
#include "anomaly.h"
#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

static int running = 1;

void handle_sigint(int sig)
{
    (void)sig;
    running = 0;
}

/**
 * Apply configuration to rule engine
 */
static void apply_config_rules(RuleEngine *engine, const Config *cfg)
{
    if(!engine || !cfg) return;

    printf("\n✓ Loading %d rules from config...\n", cfg->rule_count);

    for(int i = 0; i < cfg->rule_count; i++) {
        const RuleConfig *rc = &cfg->rules[i];

        if(!rc->enabled) {
            printf("  [SKIP] %s (disabled)\n", rc->name);
            continue;
        }

        int metric_type = config_get_metric_type(rc->metric);
        if(metric_type < 0) {
            printf("  [ERROR] %s: Unknown metric '%s'\n", rc->name, rc->metric);
            continue;
        }

        /* Add rule to engine */
        int ret = rule_engine_add_rule(
            engine,
            rc->name,
            rc->description,
            rc->severity,
            metric_type,
            rc->threshold
        );

        if(ret == 0) {
            printf("  [OK] %s (threshold: %.2f)\n", rc->name, rc->threshold);
        } else {
            printf("  [FAIL] %s\n", rc->name);
        }
    }

    printf("\n");
}

int main(int argc, char *argv[])
{
    /* Default config file */
    const char *config_file = "../ids.conf";

    /* Allow override from command line */
    if(argc > 1) {
        config_file = argv[1];
    }

    /* Load configuration */
    Config *cfg = config_load(config_file);
    if(!cfg) {
        fprintf(stderr, "ERROR: Failed to load configuration\n");
        return EXIT_FAILURE;
    }

    /* Initialize logging */
    log_init(cfg->log_level);

    printf("\n");
    printf("==========================================\n");
    printf("  NETWORK IDS - PHASE 5\n");
    printf("  Configuration-Driven System\n");
    printf("==========================================\n");
    printf("Config file: %s\n", config_file);
    printf("Sampling interval: %d seconds\n", cfg->sampling_interval);
    printf("Log level: %d\n", cfg->log_level);

    signal(SIGINT, handle_sigint);

    /* Create engines */
    RuleEngine *engine = rule_engine_create(cfg->rule_count + 5);
    AnomalyDetector *detector = anomaly_create(16);

    /* Apply configuration rules */
    apply_config_rules(engine, cfg);

    if(engine->rule_count == 0) {
        printf("WARNING: No rules loaded from configuration\n");
    }

    /* Main monitoring loop */
    printf("Starting monitoring loop...\n");
    printf("Press Ctrl+C to stop\n\n");

    Network_Snapshot *prev = NULL;
    int iteration = 0;
    int total_alerts = 0;

    while(running) {
        iteration++;

        Network_Snapshot *curr = read_snapshot();
        if(!curr) {
            log_error("Failed to read network snapshot");
            sleep(cfg->sampling_interval);
            continue;
        }

        if(prev) {
            RateSnapShot *rate =
                calculate_rates(prev, curr, cfg->sampling_interval);

            if(rate) {
                /* Display rates */
                printf("[Iteration %d]\n", iteration);
                print_rate_snapshot(rate);

                /* Rule-based detection */
                if(engine->rule_count > 0) {
                    AlertList *alerts =
                        rule_engine_evaluate(engine, rate);

                    if(alerts) {
                        if(alerts->count > 0) {
                            printf("\n====== RULE ALERTS (%d) ======\n", alerts->count);
                            print_alerts(alerts);
                            total_alerts += alerts->count;
                        }
                        alert_list_destroy(alerts);
                    }
                }

                /* Anomaly detection */
                AlertList *anom =
                    anomaly_evaluate(detector, rate);

                if(anom) {
                    if(anom->count > 0) {
                        printf("\n===== ANOMALY ALERTS (%d) =====\n", anom->count);
                        print_alerts(anom);
                        total_alerts += anom->count;
                    }
                    alert_list_destroy(anom);
                }

                destroy_rate_snapshot(rate);
            }
        }

        if(prev) {
            destroy_snapshot(prev);
        }
        prev = curr;

        sleep(cfg->sampling_interval);
    }

    /* Cleanup */
    printf("\n\n==========================================\n");
    printf("Shutting down...\n");
    printf("Total iterations: %d\n", iteration);
    printf("Total alerts: %d\n", total_alerts);
    printf("==========================================\n");

    if(prev) {
        destroy_snapshot(prev);
    }

    rule_engine_destroy(engine);
    anomaly_destroy(detector);
    config_destroy(cfg);

    return EXIT_SUCCESS;
}