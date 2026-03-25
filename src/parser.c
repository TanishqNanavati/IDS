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

    /* Skip leading whitespace (IMPORTANT) */
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