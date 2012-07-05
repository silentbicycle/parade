/* 
 * Copyright (c) 2012 Scott Vokes <vokes.s@gmail.com>
 *  
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *  
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <limits.h>
#include <err.h>

#include "types.h"

#define DEF_TASK_SZ 8

#ifdef DEBUG
#define LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define LOG(...) /* NO-OP */
#endif

/* Globals */
static struct task **tasks = NULL;    /* task vector */
static int tasks_sz = DEF_TASK_SZ;    /* upper bound for task vector */
static int task_ct = 0;               /* task count */
static int newest_task = -1;          /* newest live task */
static int max_fd = 0;       /* upper file descriptor bound for select */
static volatile int should_wait = 0;  /* flag for SIGCHLD handler */
static int live_children = 0;

/* Config */
static char *name = NULL;
static int task_limit = 10;      /* max number of tasks to spawn at once */
static int buffer_sz = 4096;     /* read buffer size for tasks */

/* Forward references */
static void kill_children_and_exit(int status);
static void spawn_task(int id);
static void read_task(int id);

/* Signal handlers */
static void handle_SIGCHLD(int sig) { should_wait = 1; }
static void handle_SIGINT(int sig) { kill_children_and_exit(SIGINT); }

static void usage() {
    fprintf(stderr,
        "usage: %s [-h] [-b BUFFER_SIZE] [-t TASK_LIMIT]\n", name);
    exit(1);
}

static void free_task(task *t) {
    live_children--;
    if (t == NULL) return;
    if (t->status != STATUS_DONE) {
        t->status = STATUS_DONE;
        free(t->name);
        free(t->cmd);
        free(t->buf);
        close(t->fd);
        free(t);
    }
}

/* Clear the should_wait flag, with signals suspended. */
static void atomic_clear_should_wait() {
    sigset_t nmask, omask;
    sigemptyset(&nmask);
    sigaddset(&nmask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &nmask, &omask) < 0) err(1, "sigprocmask");
    should_wait = 0;
    if (sigprocmask(SIG_SETMASK, &omask, NULL) < 0) err(1, "sigprocmask");
}

static void wait_for_children() {
    pid_t pid = -1;
    int status = -1;

    while ((pid = wait(&status)) > 0) {
        LOG("waited, PID %d\n", pid);
        if (status != 0) kill_children_and_exit(status);
        
        for (int i = 0; i < task_ct; i++) {
            task *t = tasks[i];
            if (t != NULL && t->pid == pid) {
                LOG("freeing task '%s'\n", t->name);
                free_task(t);
                tasks[i] = NULL;
                if (newest_task < task_ct - 1) { spawn_task(++newest_task); }
                break;
            }
        }
        if (live_children == 0) break;
    }
    if (pid == -1) {
        if (errno == EINTR) {
            errno = 0;
        } else {
            warn("wait");
        }
    }
}

static void kill_children_and_exit(int status) {
    LOG("got error, exiting\n");
    for (int i=0; i<newest_task; i++) {
        task *t = tasks[i];
        if (t && t->status == STATUS_RUNNING) {
            kill(t->pid, SIGKILL);
            (void)wait(NULL);
            t->status = STATUS_DONE;
        }
    }
    exit(status);
}

static void *alloc(size_t sz) {
    void *p = malloc(sz);
    if (p == NULL) err(1, "malloc");
    LOG("Allocated %p to %p\n", p, (char *)p + sz);
    return p;
}

static char *alloc_str(char *b, int len) {
    char *s = alloc(len + 1);
    (void)strncpy(s, b, len);
    s[len] = '\0';
    return s;
}

static void save_task(char *line, int colon, int cmd_begin, int end) {
    task *t = alloc(sizeof(*t));
    t->name = alloc_str(line, colon);
    t->cmd = alloc_str(line + cmd_begin, end - cmd_begin);
    t->buf = NULL;
    t->buf_i = 0;
    t->status = STATUS_NOT_YET_RUN;
    t->fd = -1;

    if (task_ct == tasks_sz) {
        int ntasks_sz = 2 * tasks_sz;
        if (ntasks_sz < tasks_sz) {
            fprintf(stderr, "overflow\n");
            exit(1);
        }
        task **ntasks = realloc(tasks, ntasks_sz * sizeof(task));
        if (ntasks == NULL) err(1, "realloc");
        tasks = ntasks;
        tasks_sz = ntasks_sz;
    }
    tasks[task_ct++] = t;
}

/* Read from stdin a stream of lines of the format
 * "commandname: shell command to generate output"
 *
 * If the 'commandname:' part is ommitted, the command itself is used. */
static void read_command_spec() {
    static char buf[ARG_MAX];
    char *line = NULL;

    tasks = alloc(DEF_TASK_SZ * sizeof(task));
    tasks_sz = DEF_TASK_SZ;

    while ((line = fgets(buf, ARG_MAX, stdin))) {
        int colon = -1;
        for (int i = 0; ; i++) {
            char c = line[i];
            if (c == '\0' || c == '\n') {
                if (i == 0) {
                    ;           /* ignore blank line */
                } else if (colon == -1) {
                    save_task(line, i, 0, i);
                } else {
                    int begin = colon + 1;
                    while (line[begin] == ' ') begin++;
                    save_task(line, colon, begin, i);
                }
                if (c == '\0') return;
                break;
            } else if (c == ':') {
                colon = i;
                continue;
            }
        }
    }
}

static void child_go(int fd, char *cmd) {
    dup2(fd, 1);                /* set stdout to parent's pipe */
    exit(system(cmd));
}

static void spawn_task(int id) {
    task *t = tasks[id];
    int pair[2];
    int res = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
    if (res == -1) err(1, "socketpair");
    res = fork();
    if (res == -1) {
        err(1, "fork");
    } else if (res == 0) {  /* child */
        child_go(pair[1], t->cmd);
    } else {                /* parent */
        t->pid = res;
        t->fd = pair[0];
        max_fd = (pair[0] > max_fd ? pair[0] : max_fd);
        t->buf = alloc(buffer_sz);
        LOG("allocated %p for %s\n", t->buf, t->name);
        t->status = STATUS_RUNNING;
        live_children++;
        newest_task = id;
    }
}

static void spawn_initial() {
    int lim = task_limit < task_ct ? task_limit : task_ct;
    for (int i=0; i<lim; i++) { spawn_task(i); }
}

static void read_task(int id) {
    task *t = tasks[id];
    char buf[buffer_sz];
    assert(t);
    assert(t->status == STATUS_RUNNING);

    int rd = read(t->fd, t->buf + t->buf_i, buffer_sz - t->buf_i);
    int last = 0;

    if (rd > 0) {
        int len = rd + t->buf_i;
        t->buf[len] = '\0';
        int i;
        for (i=0; i<len; i++) {
            char c = t->buf[i];
            if (c == '\n') {    /* got a full line */
                strncpy(buf, t->buf + last, i - last);
                buf[i - last] = '\0';
                printf("%s: %s\n", tasks[id]->name, buf);
                last = i + 1;
            } else if (c == '\0') {
                break;
            }
        }

        /* keep last unterminated line */
        if (i > last) {
            memmove(t->buf, t->buf + last, i - last);
            t->buf[i - last + 1] = '\0';
            t->buf_i = i - last;
        } else {
            t->buf_i = 0;
        }
    }
}

static void set_fds(fd_set *fds) {
    for (int i=0; i<=newest_task; i++) {
        task *t = tasks[i];
        if (t && t->status == STATUS_RUNNING) FD_SET(tasks[i]->fd, fds);
    }
}

static void run() {
    fd_set fds;
    /* Don't block indefinitely, so that the last read(s) from a
     * child that has already thrown a SIGCHLD will still happen. */
    struct timeval tv = {0, 100 * 1000};
    FD_ZERO(&fds);

    while (live_children > 0) {
        set_fds(&fds);
        int res = select(max_fd + 1, &fds, NULL, NULL, &tv);
        if (res > 0) {
            for (int i=0; i<=newest_task; i++) {
                task *t = tasks[i];
                if (t && FD_ISSET(t->fd, &fds)) {
                    read_task(i);
                }
            }        
        } else if (res < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                errno = 0;
            } else {                
                err(1, "select");
            }
        }

        if (res == 0 && should_wait) {
            atomic_clear_should_wait();
            wait_for_children();
        }
    }
}

static void cleanup() {
    LOG("cleanup\n");
    for (int i=0; i<task_ct; i++) {
        if (tasks[i] != NULL) free_task(tasks[i]);
    }
}

static void handle_args(int *argc, char **argv[]) {
    int f = 0;
    while ((f = getopt(*argc, *argv, "hb:t:")) != -1) {
        switch (f) {
        case 'h':               /* help */
            usage();
            break;
        case 'b':               /* buffer size */
            buffer_sz = atoi(optarg);
            if (buffer_sz < 1) {
                fprintf(stderr, "illegal buffer size: %s\n", optarg);
                exit(1);
            }
            break;
        case 't':               /* task limit */
            task_limit = atoi(optarg);
            if (buffer_sz < 1) {
                fprintf(stderr, "illegal task limit: %s\n", optarg);
                exit(1);
            }
            break;
        default:
            usage();
            /* NOTREACHED */
        }
    }
    *argc -= optind;
    *argv += optind;
}

int main(int argc, char **argv) {
    name = argv[0];
    struct sigaction sa;
    bzero(&sa, sizeof(struct sigaction));
    sa.sa_handler = handle_SIGCHLD;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGCHLD);
    sa.sa_flags = 0;
    sigaction(SIGCHLD, &sa, NULL);

    signal(SIGINT, handle_SIGINT);

    handle_args(&argc, &argv);
    read_command_spec();
    spawn_initial();
    run();
    assert(should_wait == 0);

    cleanup();
    return 0;
}
