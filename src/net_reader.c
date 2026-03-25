#include"net_reader.h"
#include<stdio.h>

static char* readfile(const char *filepath){
    FILE *f = fopen(filepath,"r");
    if(!f){
        log_error("Failed to open the file : %s",filepath);
        return NULL;
    }

    size_t buffer_size = 4096;
    size_t total_read = 0;
    char *buff = (char *)malloc(buffer_size);

    if(!buff){
        log_error("Failed to allocate buffer for file: %s", filepath);
        fclose(f);
        return NULL;
    }

    while(1){
        size_t bytes_read = fread(buff + total_read,1,buffer_size-total_read-1,f);
        if(!bytes_read) break;

        total_read += bytes_read;

        if(total_read >= buffer_size - 1){
            buffer_size *= 2;
            char *new_buff = (char *)realloc(buff,buffer_size);

            if(!new_buff){
                log_error("Failed to expand buffer file : %s",filepath);
                free(buff);
                fclose(f);
                return NULL;
            }

            buff = new_buff;
        }
    }

    fclose(f);

    if(!total_read){
        log_error("No data read from file: %s", filepath);
        free(buff);
        return NULL;
    }

    buff[total_read] = '\0';
    log_debug("Read %zu bytes from %s", total_read, filepath);
    return buff;
}

Network_Snapshot *read_snapshot(void){
    return read_file("/proc/net/dev");
}

Network_Snapshot* read_file(const char *filepath){
    if(!filepath){
        log_error("file path cannot be NULL");
        return NULL;
    }

    char *content = readfile(filepath);
    if(!content) return NULL;

    log_debug("Read %zu bytes from %s", strlen(content), filepath);

    extern Network_Snapshot *parse_file(const char *content);
    Network_Snapshot *snap = parse_file(content);

    free(content);
    return snap; 
}