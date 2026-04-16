#include"rate.h"
#include<math.h>
#include <unistd.h>

/* Console colors (disabled automatically when not attached to a TTY or when NO_COLOR is set) */
#define CLR_RESET  "\x1b[0m"
#define CLR_WHITE  "\x1b[97m"
#define CLR_RED    "\x1b[31m"
#define CLR_ORANGE "\x1b[38;5;208m"
#define CLR_BOLD   "\x1b[1m"

static int stdout_color_enabled(void)
{
    static int cached = -1;
    if(cached == -1) {
        cached = (getenv("NO_COLOR") == NULL) && isatty(STDOUT_FILENO);
    }
    return cached;
}

static const char *outc(const char *code) { return stdout_color_enabled() ? code : ""; }

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

    printf("%s[", outc(CLR_WHITE));

    printf("%s", outc(CLR_RED));
    for(int i=0;i<bars;i++) printf("#");

    printf("%s", outc(CLR_WHITE));
    for(int i=bars;i<50;i++) printf(" ");

    printf("]%s", outc(CLR_RESET));
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

    printf("\n%s====================================%s\n", outc(CLR_WHITE), outc(CLR_RESET));
    printf("%s%sNetwork Rates%s (%s%d%s interfaces, %s%.1f%s sec delta)\n",
           outc(CLR_BOLD), outc(CLR_WHITE), outc(CLR_RESET),
           outc(CLR_ORANGE), snap->count, outc(CLR_RESET),
           outc(CLR_ORANGE), snap->time_delta, outc(CLR_RESET));
    printf("%s====================================%s\n", outc(CLR_WHITE), outc(CLR_RESET));

    for (int i = 0; i < snap->count; i++) {
        const RateStats *rate = &snap->interfaces[i];
        char buf[32];

        printf("\n%s[%d]%s %s%s%s\n",
               outc(CLR_WHITE), i + 1, outc(CLR_RESET),
               outc(CLR_BOLD), rate->interface, outc(CLR_RESET));

        printf("    %sRX Bytes:%s   %s%s%s",
               outc(CLR_ORANGE), outc(CLR_RESET),
               outc(CLR_ORANGE), format_bytes(rate->recv_bytes_per_sec, buf, sizeof(buf)), outc(CLR_RESET));
        printf("  %sTX Bytes:%s   %s%s%s\n",
               outc(CLR_ORANGE), outc(CLR_RESET),
               outc(CLR_ORANGE), format_bytes(rate->tr_bytes_per_sec, buf, sizeof(buf)), outc(CLR_RESET));

        printf("    %sRX Pkts:%s %s%.2f pps%s  %sTX Pkts:%s %s%.2f pps%s\n",
               outc(CLR_WHITE), outc(CLR_RESET), outc(CLR_WHITE), rate->recv_pkts_per_sec, outc(CLR_RESET),
               outc(CLR_WHITE), outc(CLR_RESET), outc(CLR_WHITE), rate->tr_pkts_per_sec, outc(CLR_RESET));

        printf("    %sRX Graph:%s ", outc(CLR_ORANGE), outc(CLR_RESET));
        print_rate_graph(rate->recv_bytes_per_sec);
        printf("\n");
    }

    printf("\n%s====================================%s\n", outc(CLR_WHITE), outc(CLR_RESET));
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

/* Serialization for IPC */
int rate_snapshot_serialize(const RateSnapShot *snap, void *buffer, size_t buffer_size)
{
    if (!snap || !buffer) return -1;

    size_t required_size = sizeof(int) + sizeof(time_t) + sizeof(double) +
                          snap->count * sizeof(RateStats);

    if (buffer_size < required_size) return -1;

    char *ptr = (char *)buffer;

    // Serialize count
    memcpy(ptr, &snap->count, sizeof(int));
    ptr += sizeof(int);

    // Serialize timestamp
    memcpy(ptr, &snap->timestamp, sizeof(time_t));
    ptr += sizeof(time_t);

    // Serialize time_delta
    memcpy(ptr, &snap->time_delta, sizeof(double));
    ptr += sizeof(double);

    // Serialize interfaces array
    memcpy(ptr, snap->interfaces, snap->count * sizeof(RateStats));

    return required_size;
}

RateSnapShot *rate_snapshot_deserialize(const void *buffer, size_t buffer_size)
{
    if (!buffer || buffer_size < sizeof(int) + sizeof(time_t) + sizeof(double)) return NULL;

    const char *ptr = (const char *)buffer;

    // Deserialize count
    int count;
    memcpy(&count, ptr, sizeof(int));
    ptr += sizeof(int);

    size_t required_size = sizeof(int) + sizeof(time_t) + sizeof(double) +
                          count * sizeof(RateStats);

    if (buffer_size < required_size) return NULL;

    RateSnapShot *snap = create_rate_snapshot();
    if (!snap) return NULL;

    snap->count = count;

    // Deserialize timestamp
    memcpy(&snap->timestamp, ptr, sizeof(time_t));
    ptr += sizeof(time_t);

    // Deserialize time_delta
    memcpy(&snap->time_delta, ptr, sizeof(double));
    ptr += sizeof(double);

    // Deserialize interfaces array
    snap->interfaces = malloc(count * sizeof(RateStats));
    if (!snap->interfaces) {
        destroy_rate_snapshot(snap);
        return NULL;
    }

    memcpy(snap->interfaces, ptr, count * sizeof(RateStats));

    return snap;
}