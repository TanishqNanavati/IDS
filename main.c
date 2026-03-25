#include "include/common.h"
#include "include/parser.h"
#include "include/net_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>   // sleep
#include <signal.h>

static volatile int running = 1;

void handle_sigint(int sig)
{
    (void)sig;
    running = 0;
}

int main(int argc, char *argv[])
{
    log log_level = INFO;
    int interval = 3;   // default seconds

    if(argc > 1){
        int level = atoi(argv[1]);
        if(level >= DEBUG && level <= ERROR){
            log_level = (log)level;
        }
    }

    if(argc > 2){
        interval = atoi(argv[2]);
        if(interval <= 0) interval = 3;
    }

    signal(SIGINT, handle_sigint);

    log_init(log_level);
    log_info("Starting Network Telemetry Collector (Continuous Mode)");

    /* open log file in project root */
    FILE *fp = fopen("../ids_output.log", "a");
    if(!fp){
        log_error("Failed to open output file");
        return EXIT_FAILURE;
    }

    while(running){
        Network_Snapshot *snapshot = read_snapshot();

        if (!snapshot) {
            log_error("Failed to read network statistics");
            sleep(interval);
            continue;
        }

        /* print to console */
        if(global_log <= INFO){
            print_snapshot(snapshot);
        }

        /* write to file */
        fprintf(fp, "\n==== Snapshot ====\n");
        fprintf(fp, "Interfaces: %d\n", snapshot->count);

        for(int i = 0; i < snapshot->count; i++){
            NetStats *s = &snapshot->interfaces[i];

            fprintf(fp,
                "%s RX:%lu TX:%lu RXpkts:%lu TXpkts:%lu\n",
                s->interface,
                s->recv_bytes,
                s->tr_bytes,
                s->recv_pkts,
                s->tr_pkts
            );
        }

        fflush(fp);

        destroy_snapshot(snapshot);

        sleep(interval);
    }

    fclose(fp);
    log_info("Shutdown complete");
    return EXIT_SUCCESS;
}