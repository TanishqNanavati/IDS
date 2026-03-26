#include "include/common.h"
#include "include/parser.h"
#include "include/net_reader.h"
#include "include/rate.h"

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
        if(level >= DEBUG && level <= ERROR){
            log_level = (LogLevel)level;
        }
    }
    
    if(argc > 2){
        interval = atoi(argv[2]);
        if(interval <= 0) interval = 3;
    }
    
    signal(SIGINT, handle_sigint);
    log_init(log_level);
    
    log_info("Starting Network Telemetry Collector (Phase 2 - Rate Calculation)");
    log_info("Sampling interval: %d seconds", interval);
    
    FILE *fp = fopen("../ids_output.log", "a");
    if(!fp){
        log_error("Failed to open output file");
        return EXIT_FAILURE;
    }
    
    fprintf(fp, "\n\n===== PHASE 2: Rate Calculation Mode =====\n");
    fprintf(fp, "Started at: ");
    time_t now = time(NULL);
    fprintf(fp, "%s", ctime(&now));
    fprintf(fp, "Interval: %d seconds\n\n", interval);
    fflush(fp);
    
    Network_Snapshot *prev_snapshot = NULL;
    int iteration = 0;
    
    while(running){
        iteration++;
        
        log_debug("Iteration %d: Reading network statistics...", iteration);
        
        Network_Snapshot *curr_snapshot = read_snapshot();
        if (!curr_snapshot) {
            log_error("Failed to read network statistics");
            sleep(interval);
            continue;
        }
        
        if(log_level <= INFO){
            printf("\n[Iteration %d]\n", iteration);
            print_snapshot(curr_snapshot);
        }
        
        if (prev_snapshot) {
            RateSnapShot *rate_snap =
                calculate_rates(prev_snapshot, curr_snapshot, (double)interval);
            
            if (rate_snap) {
                if(log_level <= INFO){
                    print_rate_snapshot(rate_snap);
                }
                
                log_rate_snapshot(fp, rate_snap);
                fflush(fp);
                
                destroy_rate_snapshot(rate_snap);
            }
        } else {
            log_info("First iteration: Initializing rate calculation");
            
            fprintf(fp, "=== First Iteration (no rates calculated yet) ===\n");
            fprintf(fp, "Interfaces: %d\n", curr_snapshot->count);
            
            for(int i = 0; i < curr_snapshot->count; i++){
                NetStats *s = &curr_snapshot->interfaces[i];
                fprintf(fp, "  %s: RX=%lu pkts, TX=%lu pkts\n",
                        s->interface, s->recv_pkts, s->tr_pkts);
            }
            
            fprintf(fp, "\n");
            fflush(fp);
        }
        
        if (prev_snapshot) {
            destroy_snapshot(prev_snapshot);
        }
        prev_snapshot = curr_snapshot;
        
        if (running) {
            sleep(interval);
        }
    }
    
    if (prev_snapshot) {
        destroy_snapshot(prev_snapshot);
    }
    
    fprintf(fp, "\n===== Collector Shutdown =====\n");
    fclose(fp);
    
    log_info("Shutdown complete");
    return EXIT_SUCCESS;
}