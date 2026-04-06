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