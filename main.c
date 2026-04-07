#include "common.h"
#include "net_reader.h"
#include "rate.h"
#include "rule_engine.h"
#include "anomaly.h"
#include "config.h"
#include "http_server.h"

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>

static volatile sig_atomic_t running = 1;
static pid_t collector_pid = -1;

static void handle_signal(int sig)
{
    if(sig == SIGINT || sig == SIGTERM) {
        running = 0;
        if(collector_pid > 0) {
            kill(collector_pid, SIGTERM);
        }
    }
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

/**
 * Collector process: reads network data and sends to analyzer
 */
static void collector_process(int write_fd, const Config *cfg)
{
    printf("[COLLECTOR] Starting collector process (PID: %d)\n", getpid());

    Network_Snapshot *prev = NULL;
    int iteration = 0;

    while(running) {
        iteration++;

        Network_Snapshot *curr = read_snapshot();
        if(!curr) {
            log_error("Failed to read network snapshot");
            sleep(cfg->sampling_interval);
            continue;
        }

        if(prev) {
            RateSnapShot *rate = calculate_rates(prev, curr, cfg->sampling_interval);
            if(rate) {
                // Serialize and send to analyzer
                size_t buffer_size = sizeof(int) + sizeof(time_t) + sizeof(double) +
                                   rate->count * sizeof(RateStats);
                void *buffer = malloc(buffer_size);
                if(buffer) {
                    int written = rate_snapshot_serialize(rate, buffer, buffer_size);
                    if(written > 0) {
                        ssize_t bytes_written = write(write_fd, buffer, written);
                        if(bytes_written != written) {
                            if(bytes_written == -1 && errno == EPIPE) {
                                log_warn("Analyzer process closed pipe, stopping collector");
                                free(buffer);
                                destroy_rate_snapshot(rate);
                                break;
                            }
                            log_error("Failed to write to pipe");
                        } else {
                            log_debug("[COLLECTOR] Sent rate snapshot (iteration %d)", iteration);
                        }
                    }
                    free(buffer);
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

    if(prev) {
        destroy_snapshot(prev);
    }

    close(write_fd);
    printf("[COLLECTOR] Collector process exiting\n");
}

/**
 * Analyzer process: receives data and performs detection
 */
static void analyzer_process(int read_fd, const Config *cfg)
{
    printf("[ANALYZER] Starting analyzer process (PID: %d)\n", getpid());

    /* Create engines */
    RuleEngine *engine = rule_engine_create(cfg->rule_count + 5);
    AnomalyDetector *detector = anomaly_create(16);
    MetricsServer *metrics = metrics_server_create(cfg->metrics_port);

    /* Apply configuration rules */
    apply_config_rules(engine, cfg);

    if(engine->rule_count == 0) {
        printf("WARNING: No rules loaded from configuration\n");
    }

    int iteration = 0;
    int total_alerts = 0;

    while(running) {
        // Use select() to timeout on blocking read so Ctrl+C is responsive
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(read_fd, &readfds);
        
        struct timeval timeout;
        timeout.tv_sec = 2;  // Check running flag every 2 seconds
        timeout.tv_usec = 0;

        int select_ret = select(read_fd + 1, &readfds, NULL, NULL, &timeout);
        if(select_ret < 0) {
            log_error("select() failed: %s", strerror(errno));
            break;
        }
        if(select_ret == 0) {
            // Timeout: check if shutdown was requested
            if(!running) break;
            continue;
        }

        if(!FD_ISSET(read_fd, &readfds)) {
            continue;
        }

        // Read count first
        int count;
        ssize_t bytes_read = read(read_fd, &count, sizeof(int));
        if(bytes_read != sizeof(int)) {
            if(bytes_read == 0) {
                // Pipe closed
                break;
            }
            log_error("Failed to read count from pipe");
            continue;
        }

        // Calculate buffer size
        size_t buffer_size = sizeof(time_t) + sizeof(double) + count * sizeof(RateStats);
        void *buffer = malloc(buffer_size);
        if(!buffer) {
            log_error("Failed to allocate buffer");
            continue;
        }

        // Read the rest
        bytes_read = read(read_fd, buffer, buffer_size);
        if(bytes_read != (ssize_t)buffer_size) {
            log_error("Failed to read data from pipe");
            free(buffer);
            continue;
        }

        // Reconstruct the full buffer for deserialization
        void *full_buffer = malloc(sizeof(int) + buffer_size);
        if(!full_buffer) {
            log_error("Failed to allocate full buffer");
            free(buffer);
            continue;
        }

        memcpy(full_buffer, &count, sizeof(int));
        memcpy((char*)full_buffer + sizeof(int), buffer, buffer_size);

        RateSnapShot *rate = rate_snapshot_deserialize(full_buffer, sizeof(int) + buffer_size);
        free(full_buffer);
        free(buffer);

        if(!rate) {
            log_error("Failed to deserialize rate snapshot");
            continue;
        }

        iteration++;

        /* Update metrics with interface data */
        if(metrics) {
            metrics_server_update_interfaces(metrics, rate);
        }

        /* Display rates */
        printf("[Iteration %d]\n", iteration);
        print_rate_snapshot(rate);

        /* Rule-based detection */
        if(engine->rule_count > 0) {
            AlertList *alerts = rule_engine_evaluate(engine, rate);

            if(alerts) {
                if(alerts->count > 0) {
                    printf("\n====== RULE ALERTS (%d) ======\n", alerts->count);
                    print_alerts(alerts);
                    total_alerts += alerts->count;
                    
                    /* Update metrics with rule alerts */
                    if(metrics) {
                        for(int i = 0; i < alerts->count; i++) {
                            metrics_server_update_alerts(metrics, alerts->alerts[i].rule_name, time(NULL));
                        }
                    }
                }
                alert_list_destroy(alerts);
            }
        }

        /* Anomaly detection */
        AlertList *anom = anomaly_evaluate(detector, rate);

        if(anom) {
            if(anom->count > 0) {
                printf("\n===== ANOMALY ALERTS (%d) =====\n", anom->count);
                print_alerts(anom);
                total_alerts += anom->count;
                
                /* Update metrics with anomaly alerts */
                if(metrics) {
                    for(int i = 0; i < anom->count; i++) {
                        metrics_server_update_alerts(metrics, "anomaly", time(NULL));
                    }
                }
            }
            alert_list_destroy(anom);
        }

        destroy_rate_snapshot(rate);

        if(metrics) {
            metrics_server_update(metrics, iteration, total_alerts, time(NULL));
        }
    }

    /* Cleanup */
    printf("\n\n==========================================\n");
    printf("[ANALYZER] Shutting down...\n");
    printf("Total iterations: %d\n", iteration);
    printf("Total alerts: %d\n", total_alerts);
    printf("==========================================\n");

    if(metrics) {
        metrics_server_destroy(metrics);
    }
    rule_engine_destroy(engine);
    anomaly_destroy(detector);
    close(read_fd);
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
    printf("  NETWORK IDS - PHASE 6\n");
    printf("  Multi-Process Architecture\n");
    printf("==========================================\n");
    printf("Config file: %s\n", config_file);
    printf("Sampling interval: %d seconds\n", cfg->sampling_interval);
    printf("Log level: %d\n", cfg->log_level);

    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    /* Create pipe for IPC */
    int pipe_fd[2];
    if(pipe(pipe_fd) == -1) {
        perror("Failed to create pipe");
        config_destroy(cfg);
        return EXIT_FAILURE;
    }

    /* Fork processes */
    pid_t pid = fork();
    if(pid < 0) {
        perror("Failed to fork");
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        config_destroy(cfg);
        return EXIT_FAILURE;
    }

    if(pid == 0) {
        /* Child process: Collector */
        close(pipe_fd[0]); // Close read end
        collector_process(pipe_fd[1], cfg);
        config_destroy(cfg);
        exit(EXIT_SUCCESS);
    } else {
        /* Parent process: Analyzer */
        collector_pid = pid;
        close(pipe_fd[1]); // Close write end
        analyzer_process(pipe_fd[0], cfg);

        /* If shutdown was requested, ensure collector exits too */
        if(running == 0) {
            kill(collector_pid, SIGTERM);
        }

        int status;
        waitpid(pid, &status, 0);
        if(WIFEXITED(status)) {
            printf("[MAIN] Collector process exited with status %d\n", WEXITSTATUS(status));
        } else if(WIFSIGNALED(status)) {
            printf("[MAIN] Collector process terminated by signal %d\n", WTERMSIG(status));
        }
    }

    config_destroy(cfg);
    return EXIT_SUCCESS;
}