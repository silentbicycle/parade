#ifndef TYPES_H
#define TYPES_H

typedef enum {
    STATUS_NOT_YET_RUN,
    STATUS_RUNNING,
    STATUS_DONE,
} status_t;

typedef struct task {
    char *name;
    char *cmd;
    char *buf;
    int buf_i;
    pid_t pid;
    int fd;
    status_t status;
} task;

#endif
