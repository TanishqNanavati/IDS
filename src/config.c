#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    const char *name;
    int type;
} MetricMapping;

static const MetricMapping metric_map[] = {
    { "RX_BYTES", 0 },
    { "TX_BYTES", 1 },
    { "RX_PKTS", 2 },
    { "TX_PKTS", 3 },
    { "RX_ERRORS", 4 },
    { "TX_ERRORS", 5 },
    { "RX_DROPS", 6 },
    { "TX_DROPS", 7 },
    { NULL, -1 }
};


static char *trim(char *str)
{
    if(!str) return str;

    /* Trim leading whitespace */
    while(isspace((unsigned char)*str)) str++;

    /* Trim trailing whitespace */
    char *end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    return str;
}


static int parse_rule_line(const char *line, RuleConfig *out)
{
    if(!line || !out) return -1;

    /* Skip comments and empty lines */
    char *copy = malloc(strlen(line) + 1);
    if(!copy) return -1;

    strcpy(copy, line);
    trim(copy);

    if(copy[0] == '#' || copy[0] == '\0') {
        free(copy);
        return 0;  /* Skip this line */
    }

    /* Parse pipe-separated values */
    char *name = strtok(copy, "|");
    char *desc = strtok(NULL, "|");
    char *metric = strtok(NULL, "|");
    char *thresh_str = strtok(NULL, "|");
    char *sev_str = strtok(NULL, "|");
    char *enabled_str = strtok(NULL, "|");

    if(!name || !desc || !metric || !thresh_str || !sev_str) {
        free(copy);
        return -1;
    }

    /* Trim and validate */
    name = trim(name);
    desc = trim(desc);
    metric = trim(metric);
    thresh_str = trim(thresh_str);
    sev_str = trim(sev_str);

    if(strlen(name) == 0 || strlen(desc) == 0) {
        free(copy);
        return -1;
    }

    /* Get metric type */
    int metric_type = config_get_metric_type(metric);
    if(metric_type < 0) {
        printf("ERROR: Unknown metric '%s'\n", metric);
        free(copy);
        return -1;
    }

    /* Parse threshold */
    double threshold = atof(thresh_str);

    /* Parse severity */
    int severity = atoi(sev_str);
    if(severity < 0 || severity > 2) severity = 1;

    /* Parse enabled flag */
    int enabled = 1;
    if(enabled_str) {
        enabled_str = trim(enabled_str);
        enabled = atoi(enabled_str);
    }

    /* Fill output */
    strncpy(out->name, name, sizeof(out->name) - 1);
    out->name[sizeof(out->name) - 1] = '\0';

    strncpy(out->description, desc, sizeof(out->description) - 1);
    out->description[sizeof(out->description) - 1] = '\0';

    strncpy(out->metric, metric, sizeof(out->metric) - 1);
    out->metric[sizeof(out->metric) - 1] = '\0';

    out->threshold = threshold;
    out->severity = severity;
    out->enabled = enabled;

    free(copy);
    return 1;  /* Success */
}


Config *config_load(const char *filename)
{
    if(!filename) {
        printf("ERROR: Config filename is NULL\n");
        return NULL;
    }

    FILE *fp = fopen(filename, "r");
    if(!fp) {
        printf("ERROR: Cannot open config file: %s\n", filename);
        return NULL;
    }

    Config *cfg = malloc(sizeof(Config));
    if(!cfg) {
        fclose(fp);
        return NULL;
    }

    /* Initialize defaults */
    cfg->sampling_interval = 2;
    cfg->log_level = 1;
    cfg->metrics_port = 9100;
    cfg->max_rules = 32;
    cfg->rule_count = 0;
    cfg->rules = calloc(cfg->max_rules, sizeof(RuleConfig));
    strncpy(cfg->config_file, filename, sizeof(cfg->config_file) - 1);

    if(!cfg->rules) {
        free(cfg);
        fclose(fp);
        return NULL;
    }

    /* Parse file */
    char line[512];
    int in_rules_section = 0;

    while(fgets(line, sizeof(line), fp)) {
        /* Remove newline */
        char *nl = strchr(line, '\n');
        if(nl) *nl = '\0';

        /* Check for section headers */
        if(strncmp(line, "[SETTINGS]", 10) == 0) {
            in_rules_section = 0;
            continue;
        }
        if(strncmp(line, "[RULES]", 7) == 0) {
            in_rules_section = 1;
            continue;
        }

        /* Skip comments and empty lines */
        char *trimmed = trim(line);
        if(trimmed[0] == '#' || trimmed[0] == '\0') continue;

        /* Parse based on section */
        if(!in_rules_section) {
            /* Parse settings */
            char *eq = strchr(line, '=');
            if(!eq) continue;

            char *key = line;
            char *val = eq + 1;

            key = trim(key);
            val = trim(val);
            *(eq) = '\0';

            if(strcmp(key, "interval") == 0) {
                cfg->sampling_interval = atoi(val);
                if(cfg->sampling_interval <= 0) cfg->sampling_interval = 2;
            }
            else if(strcmp(key, "log_level") == 0) {
                cfg->log_level = atoi(val);
                if(cfg->log_level < 0 || cfg->log_level > 3) cfg->log_level = 1;
            }
            else if(strcmp(key, "metrics_port") == 0) {
                cfg->metrics_port = atoi(val);
                if(cfg->metrics_port <= 0 || cfg->metrics_port > 65535) cfg->metrics_port = 9100;
            }
        } else {
            /* Parse rules */
            if(cfg->rule_count >= cfg->max_rules) {
                printf("WARNING: Max rules (%d) reached\n", cfg->max_rules);
                break;
            }

            int ret = parse_rule_line(line, &cfg->rules[cfg->rule_count]);
            if(ret == 1) {
                cfg->rule_count++;
            } else if(ret < 0) {
                printf("WARNING: Failed to parse rule line: %s\n", line);
            }
        }
    }

    fclose(fp);

    printf("✓ Loaded config: %s\n", filename);
    printf("  Interval: %d seconds\n", cfg->sampling_interval);
    printf("  Log level: %d\n", cfg->log_level);
    printf("  Metrics port: %d\n", cfg->metrics_port);
    printf("  Rules: %d\n", cfg->rule_count);

    return cfg;
}


void config_destroy(Config *cfg)
{
    if(!cfg) return;
    if(cfg->rules) free(cfg->rules);
    free(cfg);
}


void config_print(const Config *cfg)
{
    if(!cfg) return;

    printf("\n=====================================\n");
    printf("Configuration: %s\n", cfg->config_file);
    printf("=====================================\n");
    printf("Sampling Interval: %d seconds\n", cfg->sampling_interval);
    printf("Log Level: %d\n", cfg->log_level);
    printf("Metrics Port: %d\n", cfg->metrics_port);
    printf("Rules: %d\n\n", cfg->rule_count);

    for(int i = 0; i < cfg->rule_count; i++) {
        const RuleConfig *r = &cfg->rules[i];
        printf("[%d] %s\n", i+1, r->name);
        printf("    Description: %s\n", r->description);
        printf("    Metric: %s\n", r->metric);
        printf("    Threshold: %.2f\n", r->threshold);
        printf("    Severity: %d\n", r->severity);
        printf("    Enabled: %s\n\n", r->enabled ? "Yes" : "No");
    }

    printf("=====================================\n\n");
}


int config_get_metric_type(const char *name)
{
    if(!name) return -1;

    for(int i = 0; metric_map[i].name; i++) {
        if(strcmp(metric_map[i].name, name) == 0) {
            return metric_map[i].type;
        }
    }

    return -1;
}


const char *config_get_metric_name(int type)
{
    for(int i = 0; metric_map[i].name; i++) {
        if(metric_map[i].type == type) {
            return metric_map[i].name;
        }
    }

    return "UNKNOWN";
}