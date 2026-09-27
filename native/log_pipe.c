/* Bounded stdout/stderr pipe adapter and canonical generation writer lease.
 * The packaged syslog-ng/supervisor may reopen /dev/stdout: Linux journal
 * sockets cannot be reopened that way, whereas this anonymous pipe can.
 * Parent holds the shared flock for the entire foreground process lifetime.
 * Private unit cgroup independently detects survivors if this parent dies.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t child_pid;
static void forward(int sig) { if (child_pid > 0) kill(-child_pid, sig); }
static void fail(const char *msg) { fprintf(stderr, "native foreground adapter: %s\n", msg); exit(111); }
static unsigned number(const char *value) {
    if (!*value || *value == '-' || *value == '+') fail("invalid account id");
    char *end; errno = 0; unsigned long parsed = strtoul(value, &end, 10);
    if (errno || *end || parsed >= UINT32_MAX) fail("invalid account id");
    return (unsigned) parsed;
}

int main(int argc, char **argv) {
    if (argc < 7 || strcmp(argv[1], "--lease-dir") || strcmp(argv[3], "--generation"))
        fail("fixed lease/generation and executable required");
    if (strcmp(argv[4], "native") && strcmp(argv[4], "legacy")) fail("invalid writer generation");
    int command = 5, credentials = 0;
    uid_t uid = 0; gid_t gid = 0, groups[64]; size_t group_count = 0;
    if (argc > 11 && !strcmp(argv[5], "--uid") && !strcmp(argv[7], "--gid") && !strcmp(argv[9], "--groups")) {
        credentials = 1; uid = number(argv[6]); gid = number(argv[8]);
        char *list = strdup(argv[10]); if (!list) fail("allocation failed");
        for (char *part = strtok(list, ","); part; part = strtok(NULL, ",")) {
            if (group_count == 64) fail("too many supplementary groups");
            groups[group_count++] = number(part);
        }
        free(list); command = 11;
    }
    if (command + 1 >= argc || strcmp(argv[command], "--")) fail("executable boundary required");
    command++;
    int directory = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (directory < 0) fail("lease directory unavailable");
    int lease = openat(directory, "lease.lock", O_RDONLY | O_NOFOLLOW);
    struct stat info;
    if (lease < 0 || fstat(lease, &info) || !S_ISREG(info.st_mode) || info.st_uid || (info.st_mode & 077) || info.st_nlink != 1)
        fail("protected lease inode required");
    if (flock(lease, LOCK_SH | LOCK_NB)) fail("writer transition in progress");
    /* Read generation AFTER locking from a directory bind; atomic replacement
     * stays visible, unlike binding a stale single generation.json inode. */
    int generation = openat(directory, "generation.json", O_RDONLY | O_NOFOLLOW);
    if (generation < 0 || fstat(generation, &info) || !S_ISREG(info.st_mode) || info.st_uid || (info.st_mode & 077) || info.st_size > 128)
        fail("protected generation record required");
    char record[129] = {0}; ssize_t size = read(generation, record, 128);
    close(generation); close(directory);
    if (size < 0) fail("generation read failed");
    char expected[64]; snprintf(expected, sizeof expected, "{\"generation\": \"%s\"}", argv[4]);
    if (strcmp(record, expected)) fail("runtime is not canonical writer generation");
    int pipes[2]; if (pipe2(pipes, O_CLOEXEC)) fail("pipe failed");
    struct sigaction action = {0}; action.sa_handler = forward; sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL); sigaction(SIGINT, &action, NULL); sigaction(SIGHUP, &action, NULL);
    signal(SIGPIPE, SIG_IGN);
    pid_t pid = fork(); if (pid < 0) fail("fork failed");
    if (!pid) {
        setpgid(0, 0); close(pipes[0]); close(lease);
        if (dup2(pipes[1], STDOUT_FILENO) < 0 || dup2(pipes[1], STDERR_FILENO) < 0) _exit(111);
        close(pipes[1]);
        if (credentials && (setgroups(group_count, groups) || setgid(gid) || setuid(uid))) _exit(111);
        execv(argv[command], &argv[command]); _exit(111);
    }
    child_pid = pid; setpgid(pid, pid); close(pipes[1]);
    char buffer[16384]; ssize_t count;
    for (;;) {
        count = read(pipes[0], buffer, sizeof buffer);
        if (!count) break;
        if (count < 0) { if (errno == EINTR) continue; forward(SIGTERM); break; }
        for (ssize_t written = 0; written < count;) {
            ssize_t part = write(STDOUT_FILENO, buffer + written, count - written);
            if (part < 0) { if (errno == EINTR) continue; forward(SIGTERM); goto done; }
            written += part;
        }
    }
done:
    close(pipes[0]); int status;
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) fail("wait failed");
    close(lease);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
