#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <time.h>

typedef struct MetricsServer MetricsServer;

MetricsServer *metrics_server_create(int port);
void metrics_server_destroy(MetricsServer *server);
void metrics_server_update(MetricsServer *server,
                           unsigned long total_iterations,
                           unsigned long total_alerts,
                           time_t last_update);

#endif
