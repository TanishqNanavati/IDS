#ifndef CONFIG_H
#define CONFIG_H

#include "rule_engine.h"

// Configuration structure for a rule
typedef struct {
    char name[64];              
    char description[256];      
    char metric[32];            // Metric name (RX_BYTES, TX_PKTS, etc.) 
    double threshold;           // Alert threshold 
    int severity;               // 0=INFO, 1=WARN, 2=CRITICAL 
    int enabled;                // 1=enabled, 0=disabled 
} RuleConfig;

// Global configuration
typedef struct {
    int sampling_interval;      // Seconds between samples 
    int log_level;              // 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR 
    int max_rules;              // Maximum rules to load 
    RuleConfig *rules;          // Array of rules 
    int rule_count;             // Number of loaded rules 
    char config_file[256];      // Path to config file 
} Config;


Config *config_load(const char *filename);

void config_destroy(Config *cfg);

void config_print(const Config *cfg);

int config_get_metric_type(const char *name);

const char *config_get_metric_name(int type);

#endif