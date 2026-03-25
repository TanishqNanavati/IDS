#include "common.h"
#include <stdarg.h>

log global_log = INFO;


static const char* log_str(log l)
{
    switch(l){
        case DEBUG:
            return "DEBUG";
        case INFO:
            return "INFO";
        case WARN:
            return "WARN";
        case ERROR:
            return "ERROR";
        default:
            return "UNKNOWN";
    }
}


void log_init(log l)
{
    global_log = l;
}


void log_msg(log l, const char* fmt, ...)
{
   
    if(l < global_log) return;
    
  
    time_t now = time(NULL);
    struct tm* timeinfo = localtime(&now);
    
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
  
    fprintf(stderr, "[%s] [%-5s] ", timestamp, log_str(l));
    
   
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    /* Print newline */
    fprintf(stderr, "\n");
}


Network_Snapshot *create_snapshot(void)
{
    Network_Snapshot* snap = (Network_Snapshot*)malloc(sizeof(Network_Snapshot));
    if(!snap){
        log_error("Failed to allocate Network_Snapshot");
        return NULL;
    }
    snap->interfaces = NULL;
    snap->count = 0;
    snap->timestamp = time(NULL);
    return snap;
}


void destroy_snapshot(Network_Snapshot* snap)
{
    if(!snap) return;
    if(snap->interfaces){
        free(snap->interfaces);
        snap->interfaces = NULL;
    }
    free(snap);
}