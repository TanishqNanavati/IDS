// to parse network stats from /proc/net/dev to network statistics

#ifndef PARSER_H
#define PARSER_H

#include "common.h"

// to parse a single line from /proc/net/dev
// returns --> 0 on success or -1 on error

int parse_line(const char *line,NetStats *out);

// to parse the entire file /proc/net/dev content

Network_Snapshot* parse_file(const char* content);


// utility function to print network snapshot

void print_snapshot(const Network_Snapshot* snap);

#endif