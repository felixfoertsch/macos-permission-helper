/*
 * claudehost — a TCC-responsible broker for a single, signature-verified target
 * binary on macOS.
 *
 * Problem: TCC grants (Full Disk Access etc.) key to the code identity of the
 * *responsible* process. Claude Code's binary moves to a new versioned path on
 * every auto-update, so a grant made to it dies within days; and a
 * launchd-spawned cron tree is its own responsible process, so grants made
 * interactively never covered it in the first place.
 *
 * Shape: this binary runs as a launchd agent from a stable app bundle
 * (e.g. /Applications/ClaudeHost.app). launchd-spawned => self-responsible, so
 * TCC attributes it — and every child it spawns — to that bundle, whose
 * identity never changes. Clients connect over a same-user unix socket, pass
 * argv + env + cwd + their real stdio fds, and the server spawns the target as
 * its own child.
 *
 * The gate: the server takes NO target binary from the caller. It resolves the
 * target path it was configured with at startup and verifies it against a
 * designated requirement before every spawn (result cached by
 * dev/ino/mtime/size). Driving the socket can only ever mean "run the verified
 * target".
 *
 * Modes (argv):
 *   --claudehost-serve [opts]   run the broker (launchd agent)
 *   --claudehost-check <path> [--requirement <req>]
 *                               verify a binary against the requirement
 *   anything else               client: behaves like `<target> "$@"`
 *
 * Server options:
 *   --target <path>        binary to broker (default ~/.local/bin/claude)
 *   --requirement <req>    codesign designated requirement the target must
 *                          satisfy (default: Anthropic's claude-code)
 *   --socket <path>        listen address (default under Application Support)
 *
 * Client exit codes: the child's exit code, or 128+signal; 95 = server refused
 * (verification/spawn failure), 96 = protocol error, 97 = server vanished.
 * If the server is unreachable the client warns LOUDLY on stderr and execs the
 * target directly (same behavior as if claudehost did not exist, minus grants).
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include "PermissionWindow.h"

extern char **environ;

#define MAGIC 0x434C4831u /* "CLH1" */
#define MAX_BLOB (8u << 20)
#define ABANDON_GRACE_SEC 5

/* Anthropic's designated requirement for the claude CLI, read verbatim from
 * the shipping binary (codesign -d -r-). The bracketed OIDs are the Developer
 * ID intermediate + leaf marker extensions. */
static const char *kDefaultRequirement =
    "identifier opencode and anchor apple generic and "
    "certificate 1[field.1.2.840.113635.100.6.2.6] and "
    "certificate leaf[field.1.2.840.113635.100.6.1.13] and "
    "certificate leaf[subject.OU] = \"5NZ4Q7NXJ4\"";

#define DEFAULT_TARGET_REL ".local/bin/opencode2"

/* Set once at startup; never from a client request. */
static const char *g_requirement = NULL;
static char g_target[PATH_MAX] = "";

/* ---------- small utils ---------- */

static const char *home_dir(void) {
    const char *h = getenv("HOME");
    if (h && *h) return h;
    struct passwd *pw = getpwuid(getuid());
    return pw ? pw->pw_dir : "/tmp";
}

/* Socket path: --socket / $CLAUDEHOST_SOCKET / default under ~/Library. */
static void sock_path(const char *override, char *buf, size_t n) {
    const char *env = getenv("CLAUDEHOST_SOCKET");
    if (override && *override) snprintf(buf, n, "%s", override);
    else if (env && *env) snprintf(buf, n, "%s", env);
    else
        snprintf(buf, n,
                 "%s/Library/Application Support/macOS Permission Helper/opencode2.sock",
                 home_dir());
}

/* sun_path is 104 bytes; silent truncation would make client and server
 * disagree about the address, so refuse instead. */
static int sock_addr(const char *path, struct sockaddr_un *sa) {
    if (strlen(path) >= sizeof sa->sun_path) {
        fprintf(stderr, "claudehost: socket path too long (%zu >= %zu): %s\n",
                strlen(path), sizeof sa->sun_path, path);
        return -1;
    }
    memset(sa, 0, sizeof *sa);
    sa->sun_family = AF_UNIX;
    strcpy(sa->sun_path, path);
    return 0;
}

/* Default target when no --target was given: ~/.local/bin/claude. */
static void default_target(char *buf, size_t n) {
    const char *env = getenv("CLAUDEHOST_TARGET");
    if (env && *env) snprintf(buf, n, "%s", env);
    else snprintf(buf, n, "%s/%s", home_dir(), DEFAULT_TARGET_REL);
}

static int read_all(int fd, void *buf, size_t n) {
    char *p = buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}

static int write_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n) {
        ssize_t r = write(fd, p, n);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        p += r; n -= (size_t)r;
    }
    return 0;
}

/* ---------- signature verification ---------- */

static int verify_target(const char *path, char *err, size_t errlen) {
    int rc = -1;
    CFURLRef url = NULL;
    SecStaticCodeRef code = NULL;
    SecRequirementRef req = NULL;
    CFErrorRef cferr = NULL;
    CFStringRef reqstr =
        CFStringCreateWithCString(NULL, g_requirement, kCFStringEncodingUTF8);

    if (err && errlen) err[0] = 0;
    url = CFURLCreateFromFileSystemRepresentation(
        NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (!url) { snprintf(err, errlen, "CFURL failed"); goto out; }
    if (SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) != errSecSuccess) {
        snprintf(err, errlen, "SecStaticCodeCreateWithPath failed");
        goto out;
    }
    if (SecRequirementCreateWithString(reqstr, kSecCSDefaultFlags, &req) !=
        errSecSuccess) {
        snprintf(err, errlen, "requirement parse failed");
        goto out;
    }
    if (SecStaticCodeCheckValidityWithErrors(code, kSecCSDefaultFlags, req,
                                             &cferr) != errSecSuccess) {
        if (cferr) {
            CFStringRef d = CFErrorCopyDescription(cferr);
            if (d) {
                CFStringGetCString(d, err, (CFIndex)errlen, kCFStringEncodingUTF8);
                CFRelease(d);
            }
        }
        if (err && !err[0]) snprintf(err, errlen, "signature check failed");
        goto out;
    }
    rc = 0;
out:
    if (cferr) CFRelease(cferr);
    if (req) CFRelease(req);
    if (code) CFRelease(code);
    if (url) CFRelease(url);
    if (reqstr) CFRelease(reqstr);
    return rc;
}

/* Resolve the configured target through symlinks (CC's ~/.local/bin/claude
 * points at the current versioned binary). */
static int resolve_target(char *out, size_t n) {
    char *rp = realpath(g_target, NULL);
    if (!rp) return -1;
    snprintf(out, n, "%s", rp);
    free(rp);
    return 0;
}

/* ---------- request blob (client builds, handler parses) ----------
 * u32 argc, argc * (u32 len, bytes)   -- target args (no argv[0])
 * u32 envc, envc * (u32 len, bytes)   -- KEY=VALUE
 * u32 cwdlen, bytes
 */

struct blob { char *p; size_t len, cap; };

static void blob_bytes(struct blob *b, const void *d, size_t n) {
    if (b->len + n > b->cap) {
        b->cap = (b->len + n) * 2 + 256;
        b->p = realloc(b->p, b->cap);
        if (!b->p) { perror("realloc"); exit(96); }
    }
    memcpy(b->p + b->len, d, n);
    b->len += n;
}

static void blob_u32(struct blob *b, uint32_t v) { blob_bytes(b, &v, 4); }

static void blob_str(struct blob *b, const char *s) {
    uint32_t n = (uint32_t)strlen(s);
    blob_u32(b, n);
    blob_bytes(b, s, n);
}

struct cursor { const char *p; size_t left; };

static int cur_u32(struct cursor *c, uint32_t *v) {
    if (c->left < 4) return -1;
    memcpy(v, c->p, 4);
    c->p += 4; c->left -= 4;
    return 0;
}

/* returns a fresh NUL-terminated copy */
static char *cur_str(struct cursor *c) {
    uint32_t n;
    if (cur_u32(c, &n) || c->left < n) return NULL;
    char *s = malloc((size_t)n + 1);
    if (!s) return NULL;
    memcpy(s, c->p, n);
    s[n] = 0;
    c->p += n; c->left -= n;
    return s;
}

/* ---------- server ---------- */

static void log_line(const char *fmt, ...) {
    va_list ap;
    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(stderr, "[%s] ", ts);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

static int send_msg(int fd, char type, int32_t val) {
    char buf[5];
    buf[0] = type;
    memcpy(buf + 1, &val, 4);
    return write_all(fd, buf, 5);
}

static void send_err(int fd, const char *msg) {
    /* 'E', i32 0, u32 len, bytes */
    uint32_t n = (uint32_t)strlen(msg);
    send_msg(fd, 'E', 0);
    write_all(fd, &n, 4);
    write_all(fd, msg, n);
}

/* Handler child: owns one connection. `path` verified iff ok. */
static void handle_conn(int conn, const char *path, int ok, const char *why) {
    signal(SIGCHLD, SIG_DFL);

    /* first message: 4-byte magic + 3 stdio fds via SCM_RIGHTS */
    uint32_t magic = 0;
    int fds[3] = {-1, -1, -1};
    {
        struct iovec iov = {.iov_base = &magic, .iov_len = 4};
        union { struct cmsghdr h; char buf[CMSG_SPACE(sizeof(int) * 3)]; } cm;
        struct msghdr mh = {0};
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = cm.buf;
        mh.msg_controllen = sizeof cm.buf;
        ssize_t r;
        do { r = recvmsg(conn, &mh, 0); } while (r < 0 && errno == EINTR);
        if (r != 4 || magic != MAGIC) _exit(0);
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
                c->cmsg_len == CMSG_LEN(sizeof(int) * 3))
                memcpy(fds, CMSG_DATA(c), sizeof(int) * 3);
        }
        if (fds[0] < 0 || fds[1] < 0 || fds[2] < 0) {
            send_err(conn, "claudehost: stdio fds missing");
            _exit(0);
        }
    }

    uint32_t blen = 0;
    if (read_all(conn, &blen, 4) || blen > MAX_BLOB) _exit(0);
    char *blob = malloc(blen);
    if (!blob || read_all(conn, blob, blen)) _exit(0);

    struct cursor c = {.p = blob, .left = blen};
    uint32_t argc = 0, envc = 0;
    if (cur_u32(&c, &argc) || argc > 4096) _exit(0);
    char **argv = calloc((size_t)argc + 2, sizeof(char *));
    argv[0] = (char *)path;
    for (uint32_t i = 0; i < argc; i++)
        if (!(argv[i + 1] = cur_str(&c))) _exit(0);
    if (cur_u32(&c, &envc) || envc > 4096) _exit(0);
    char **envp = calloc((size_t)envc + 1, sizeof(char *));
    for (uint32_t i = 0; i < envc; i++)
        if (!(envp[i] = cur_str(&c))) _exit(0);
    char *cwd = cur_str(&c);
    if (!cwd) _exit(0);

    if (!ok) {
        char msg[512];
        snprintf(msg, sizeof msg,
                 "claudehost: REFUSED - %s failed signature verification (%s)",
                 path, why && *why ? why : "unknown");
        send_err(conn, msg);
        _exit(0);
    }

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fds[0], 0);
    posix_spawn_file_actions_adddup2(&fa, fds[1], 1);
    posix_spawn_file_actions_adddup2(&fa, fds[2], 2);
    posix_spawn_file_actions_addchdir(&fa, cwd);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    sigset_t all, none;
    sigfillset(&all);
    sigemptyset(&none);
    posix_spawnattr_setsigdefault(&attr, &all);
    posix_spawnattr_setsigmask(&attr, &none);
    posix_spawnattr_setpgroup(&attr, 0);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF |
                                        POSIX_SPAWN_SETSIGMASK |
                                        POSIX_SPAWN_SETPGROUP);

    pid_t pid = 0;
    int rc = posix_spawn(&pid, path, &fa, &attr, argv, envp);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    for (int i = 0; i < 3; i++) close(fds[i]);
    if (rc != 0) {
        char msg[512];
        snprintf(msg, sizeof msg, "claudehost: spawn failed: %s", strerror(rc));
        send_err(conn, msg);
        _exit(0);
    }

    /* supervise: forward K messages, report exit, kill on client vanish */
    for (;;) {
        struct pollfd pf = {.fd = conn, .events = POLLIN};
        int pr = poll(&pf, 1, 250);
        if (pr > 0) {
            char t;
            ssize_t r = read(conn, &t, 1);
            if (r == 1 && t == 'K') {
                int32_t signo;
                if (read_all(conn, &signo, 4)) r = 0;
                else if (signo > 0 && signo < NSIG) killpg(pid, signo);
            }
            if (r <= 0) { /* client vanished: reap the tree */
                killpg(pid, SIGTERM);
                for (int i = 0; i < ABANDON_GRACE_SEC * 10; i++) {
                    if (waitpid(pid, NULL, WNOHANG) > 0) _exit(0);
                    usleep(100000);
                }
                killpg(pid, SIGKILL);
                waitpid(pid, NULL, 0);
                _exit(0);
            }
        }
        int st;
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w > 0) {
            int32_t code = WIFEXITED(st) ? WEXITSTATUS(st)
                                         : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
            send_msg(conn, 'X', code);
            _exit(0);
        }
    }
}

static int serve(const char *sock_override) {
    char sp[PATH_MAX], dir[PATH_MAX];
    sock_path(sock_override, sp, sizeof sp);
    struct sockaddr_un sa;
    if (sock_addr(sp, &sa)) return 1;

    snprintf(dir, sizeof dir, "%s", sp);
    char *slash = strrchr(dir, '/');
    if (slash) { *slash = 0; mkdir(dir, 0700); }
    unlink(sp);

    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ls < 0) { perror("socket"); return 1; }
    mode_t om = umask(0077);
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) || listen(ls, 16)) {
        perror("bind/listen");
        return 1;
    }
    umask(om);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    struct stat cache_st;
    int cache_ok = 0, have_cache = 0;
    char cache_why[512] = "";
    char path[PATH_MAX] = "";

    log_line("claudehost serving on %s", sp);
    log_line("target %s", g_target);
    log_line("requirement %s", g_requirement);
    for (;;) {
        int conn = accept(ls, NULL, NULL);
        if (conn < 0) { if (errno == EINTR) continue; perror("accept"); return 1; }

        int ok = 0;
        char why[512] = "";
        if (resolve_target(path, sizeof path)) {
            snprintf(why, sizeof why, "cannot resolve %s", g_target);
        } else {
            struct stat st;
            if (stat(path, &st)) {
                snprintf(why, sizeof why, "stat: %s", strerror(errno));
            } else if (have_cache && st.st_dev == cache_st.st_dev &&
                       st.st_ino == cache_st.st_ino &&
                       st.st_size == cache_st.st_size &&
                       st.st_mtimespec.tv_sec == cache_st.st_mtimespec.tv_sec) {
                ok = cache_ok;
                snprintf(why, sizeof why, "%s", cache_why);
            } else {
                ok = verify_target(path, why, sizeof why) == 0;
                cache_st = st;
                cache_ok = ok;
                have_cache = 1;
                snprintf(cache_why, sizeof cache_why, "%s", why);
                log_line("verified %s: %s%s%s", path, ok ? "OK" : "REJECTED",
                         ok ? "" : " - ", ok ? "" : why);
            }
        }
        if (!ok) log_line("refusing request: %s (%s)", path, why);

        pid_t h = fork();
        if (h == 0) {
            close(ls);
            handle_conn(conn, path, ok, why);
            _exit(0);
        }
        close(conn);
    }
}

/* ---------- client ---------- */

static volatile sig_atomic_t g_pending_sig = 0;
static void on_sig(int s) { g_pending_sig = s; }

static void fallback_exec(int argc, char **argv, const char *reason) {
    char path[PATH_MAX];
    if (resolve_target(path, sizeof path)) {
        fprintf(stderr, "claudehost: FATAL: %s and %s missing\n", reason,
                g_target);
        exit(97);
    }
    fprintf(stderr,
            "claudehost: WARNING: %s - exec'ing %s DIRECTLY (no helper TCC "
            "grants for this run)\n",
            reason, path);
    char **av = calloc((size_t)argc + 1, sizeof(char *));
    av[0] = path;
    for (int i = 1; i < argc; i++) av[i] = argv[i];
    execv(path, av);
    fprintf(stderr, "claudehost: exec failed: %s\n", strerror(errno));
    exit(97);
}

static int run_client(int argc, char **argv) {
    char sp[PATH_MAX];
    sock_path(NULL, sp, sizeof sp);
    struct sockaddr_un sa;
    if (sock_addr(sp, &sa)) fallback_exec(argc, argv, "bad socket path");
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0 || connect(s, (struct sockaddr *)&sa, sizeof sa)) {
        fallback_exec(argc, argv, "broker unreachable");
    }

    /* magic + stdio fds */
    {
        uint32_t magic = MAGIC;
        struct iovec iov = {.iov_base = &magic, .iov_len = 4};
        union { struct cmsghdr h; char buf[CMSG_SPACE(sizeof(int) * 3)]; } cm;
        memset(&cm, 0, sizeof cm);
        struct msghdr mh = {0};
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = cm.buf;
        mh.msg_controllen = CMSG_LEN(sizeof(int) * 3);
        struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int) * 3);
        int fds[3] = {0, 1, 2};
        memcpy(CMSG_DATA(c), fds, sizeof fds);
        if (sendmsg(s, &mh, 0) != 4) fallback_exec(argc, argv, "handshake failed");
    }

    struct blob b = {0};
    blob_u32(&b, (uint32_t)(argc - 1));
    for (int i = 1; i < argc; i++) blob_str(&b, argv[i]);
    uint32_t envc = 0;
    for (char **e = environ; *e; e++) envc++;
    blob_u32(&b, envc);
    for (char **e = environ; *e; e++) blob_str(&b, *e);
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof cwd)) snprintf(cwd, sizeof cwd, "/");
    blob_str(&b, cwd);

    uint32_t blen = (uint32_t)b.len;
    if (write_all(s, &blen, 4) || write_all(s, b.p, b.len)) {
        fprintf(stderr, "claudehost: send failed\n");
        return 96;
    }
    free(b.p);

    struct sigaction sact = {.sa_handler = on_sig};
    sigemptyset(&sact.sa_mask);
    sigaction(SIGTERM, &sact, NULL);
    sigaction(SIGINT, &sact, NULL);
    sigaction(SIGHUP, &sact, NULL);
    sigaction(SIGQUIT, &sact, NULL);
    signal(SIGPIPE, SIG_IGN);

    for (;;) {
        if (g_pending_sig) {
            char buf[5] = {'K'};
            int32_t sg = g_pending_sig;
            g_pending_sig = 0;
            memcpy(buf + 1, &sg, 4);
            write_all(s, buf, 5);
        }
        struct pollfd pf = {.fd = s, .events = POLLIN};
        int pr = poll(&pf, 1, 1000);
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) continue;
        char t;
        ssize_t r = read(s, &t, 1);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) {
            fprintf(stderr, "claudehost: server closed unexpectedly\n");
            return 97;
        }
        int32_t val;
        if (read_all(s, &val, 4)) return 96;
        if (t == 'X') return (int)val;
        if (t == 'E') {
            uint32_t n;
            if (read_all(s, &n, 4) || n > 65536) return 96;
            char *msg = malloc((size_t)n + 1);
            if (!msg || read_all(s, msg, n)) return 96;
            msg[n] = 0;
            fprintf(stderr, "%s\n", msg);
            return 95;
        }
        return 96;
    }
}

/* ---------- main ---------- */

static const char *opt_val(int argc, char **argv, int *i, const char *name) {
    if (*i + 1 >= argc) {
        fprintf(stderr, "claudehost: %s needs a value\n", name);
        exit(2);
    }
    return argv[++(*i)];
}

int main(int argc, char **argv) {
    g_requirement = kDefaultRequirement;

    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--permissions") == 0))
        return run_permission_window();

    if (argc >= 2 && strcmp(argv[1], "--claudehost-serve") == 0) {
        const char *sock = NULL, *target = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--target") == 0)
                target = opt_val(argc, argv, &i, "--target");
            else if (strcmp(argv[i], "--requirement") == 0)
                g_requirement = opt_val(argc, argv, &i, "--requirement");
            else if (strcmp(argv[i], "--socket") == 0)
                sock = opt_val(argc, argv, &i, "--socket");
            else {
                fprintf(stderr, "claudehost: unknown server option %s\n", argv[i]);
                return 2;
            }
        }
        if (target) snprintf(g_target, sizeof g_target, "%s", target);
        else default_target(g_target, sizeof g_target);
        return serve(sock);
    }

    if (argc >= 3 && strcmp(argv[1], "--claudehost-check") == 0) {
        const char *path = argv[2];
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--requirement") == 0)
                g_requirement = opt_val(argc, argv, &i, "--requirement");
            else {
                fprintf(stderr, "claudehost: unknown check option %s\n", argv[i]);
                return 2;
            }
        }
        char err[512];
        if (verify_target(path, err, sizeof err) == 0) {
            printf("OK: %s satisfies the requirement\n", path);
            return 0;
        }
        printf("REJECTED: %s - %s\n", path, err);
        return 1;
    }

    /* client: the target is only used for the loud direct-exec fallback */
    default_target(g_target, sizeof g_target);
    return run_client(argc, argv);
}
