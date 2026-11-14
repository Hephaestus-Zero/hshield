/*
 * hshield.c — Phase 5 Zero-Overhead Kernel & Cognitive General Immunity Engine
 *
 * Architecture:
 *   1. Linux Landlock LSM + PR_SET_NO_NEW_PRIVS (`hshield sandbox`) — 0.00% CPU
 *      kernel isolation of ~/.ssh, ~/.gnupg, hvault, Chrome cookies, agent configs,
 *      and system/user persistence paths.
 *   2. Synchronous Kernel Canary Traps & Vault Guard (`fanotify` FAN_OPEN_PERM) —
 *      0-byte leak kernel-level EPERM + <0.1 ms SIGSTOP Amber Freeze on unauthorized open.
 *   3. Event-Driven Kernel Exec Radar (`NETLINK_CONNECTOR` / `CN_PROC` PROC_EVENT_EXEC)
 *      + On-Demand Micro-Inspector (`timerfd`, 0 idle wakeups/sec = 0.00% idle CPU):
 *      - <0.08 ms 0-token compiled antibody block (`/dev/shm/hephaestus_shield_rules.bin`)
 *      - Fileless `memfd_create` (`fexecve` -> `/memfd:...`) detection & RAM ELF capture
 *      - `LD_PRELOAD` injection, reverse shells (`fd 0,1 -> remote socket`), cryptominers
 *      - Anonymous `rwxp` shellcode memory & untrusted `io_uring` + external C2 sockets
 *   4. Persistence & Integrity Shield (`inotify`) + Autonomous AI Surgeon (`Doctor`):
 *      - Sub-ms forensic snapshot (`maps`, `fds`, TCP sockets, parent chain, `hslice`)
 *      - Process-tree eradication (`SIGKILL`) strictly preserving Sacred Core
 *      - OpenSSL AES-256-GCM binary/RAM-ELF quarantine (`~/.local/state/hephaestus/quarantine`)
 *      - `nftables` (`inet hephaestus_shield`) C2 IP block + persistence hook cleanup
 *      - <30 ms Btrfs CoW single-file surgical rollback (`hrollback restore-file`)
 *      - Autonomous Antibody Synthesis (`shield_rules.bin` + `ZeroMemory` via `hzm`)
 *
 * Build:
 *   gcc -std=c11 -O3 -march=native -flto -Wall -Wextra -Werror -s -o hshield src/hshield.c -lcrypto
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/fs.h>
#include <linux/landlock.h>
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif
#ifndef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#endif
#ifndef LANDLOCK_SCOPE_SIGNAL
#define LANDLOCK_SCOPE_SIGNAL (1ULL << 1)
#endif
#include <linux/netlink.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/fanotify.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <elf.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>

#define HSHIELD_VERSION        "5.1.0"
#define HSHIELD_RULE_MAGIC     0x48534844U /* "HSHD" */
#define HSHIELD_RULE_VERSION   1U
#define HSHIELD_MAX_RULES      512

#define SHM_STATUS_PATH        "/dev/shm/hephaestus_shield_status.json"
#define SHM_RULES_BIN_PATH     "/dev/shm/hephaestus_shield_rules.bin"
#define ETC_DIR_PATH           "/etc/hephaestus"
#define ETC_RULES_JSON_PATH    "/etc/hephaestus/shield_rules.json"
#define ETC_MCP_PINS_PATH      "/etc/hephaestus/mcp_pins.json"
#define ETC_QKEY_PATH          "/etc/hephaestus/quarantine.key"
#define CTRL_SOCK_PATH         "/run/hephaestus-shield.sock"

#define USER_HOME              "/home/user"
#define USER_UID               1000
#define USER_GID               1000
#define STATE_BASE_DIR         "/var/lib/hshield"
#define QUARANTINE_DIR         "/var/lib/hshield/quarantine"
#define FORENSICS_DIR          "/var/lib/hshield/forensics"
#define VAULT_DIR              "/etc/hshield/vault"
#define VAULT_ENC_PATH         "/etc/hshield/vault/vault.enc"

typedef struct {
    uint8_t  sha256[32];
    uint8_t  has_sha256;
    uint8_t  has_pattern;
    uint8_t  severity;
    uint8_t  reserved;
    uint32_t hit_count;
    uint64_t created_ts;
    char     pattern[128];
    char     reason[96];
} ShieldRuleBin;

typedef struct {
    uint32_t      magic;
    uint32_t      version;
    uint32_t      count;
    uint32_t      total_blocks;
    ShieldRuleBin rules[HSHIELD_MAX_RULES];
} ShieldRuleTable;

/* Kernel ABI-compatible minimal Landlock ruleset structs */
struct ll_ruleset_abi_v1 {
    __u64 handled_access_fs;
};

struct ll_ruleset_abi_v6 {
    __u64 handled_access_fs;
    __u64 handled_access_net;
    __u64 scoped;
};

typedef struct {
    int  wd;
    bool is_integrity_target;
    char path[512];
} InotifyWatchEntry;

typedef struct {
    char     path[512];
    uint64_t mod_ns;
    bool     is_integrity_target;
    bool     was_created;
} RecentModEntry;

typedef struct {
    pid_t pid;
    pid_t ppid;
    pid_t pgid;
    uid_t uid;
    char  comm[64];
    char  exe[512];
    char  cwd[512];
    char  cmdline[1024];
    char  script_arg[512];
} ProcMeta;

#define MAX_PREV_RW_VMAS 24
typedef struct {
    uint64_t start;
    uint64_t end;
} VmaRange;

typedef struct {
    pid_t    pid;
    uint64_t due_ns;
    int      stage;
    int      prev_rw_cnt;
    VmaRange prev_rw[MAX_PREV_RW_VMAS];
    ProcMeta pm;
} PendingInspect;

static volatile sig_atomic_t g_stop = 0;
static ShieldRuleTable *g_rules_shm = NULL;
static int g_rules_fd = -1;
static int g_ino_fd_global = -1;
static uint8_t g_qkey[32];
static bool g_qkey_loaded = false;

static bool        g_shadow_mode = false;
static bool        g_disable_fanotify = false;
static const char *g_status_shm_path = SHM_STATUS_PATH;
static const char *g_rules_shm_path  = SHM_RULES_BIN_PATH;
static const char *g_rules_json_path = ETC_RULES_JSON_PATH;
static const char *g_ctrl_sock_path  = CTRL_SOCK_PATH;
static const char *g_forensics_dir   = FORENSICS_DIR;
static const char *g_quarantine_dir  = QUARANTINE_DIR;

static uint64_t g_boot_ts = 0;
static uint32_t g_incidents_total = 0;
static uint32_t g_canary_blocks = 0;
static uint32_t g_immune_fast_blocks = 0;
static uint32_t g_files_restored = 0;
static uint64_t g_last_freeze_us = 0;
static char     g_last_incident[160] = "none";

#define MAX_INOTIFY_WATCHES 64
static InotifyWatchEntry g_watches[MAX_INOTIFY_WATCHES];
static int g_watch_count = 0;

#define MAX_RECENT_MODS 64
static RecentModEntry g_recent_mods[MAX_RECENT_MODS];
static int g_recent_mod_idx = 0;

#define MAX_PENDING_INSPECT 256
static PendingInspect g_pending[MAX_PENDING_INSPECT];

/* Prevent duplicate triage on rapid multi-event bursts for the same PID */
#define MAX_HANDLED_PIDS 64
static pid_t    g_handled_pids[MAX_HANDLED_PIDS];
static uint64_t g_handled_ns[MAX_HANDLED_PIDS];
static int      g_handled_idx = 0;

static void on_sigterm(int sig) {
    (void)sig;
    g_stop = 1;
}

static uint64_t mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static ssize_t read_file_fast(const char *path, char *buf, size_t cap) {
    if (cap == 0) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        buf[0] = '\0';
        return -1;
    }
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0) {
        buf[0] = '\0';
        return -1;
    }
    buf[n] = '\0';
    return n;
}

static bool write_file_atomic(const char *path, const void *data, size_t len, mode_t mode) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%.980s.tmp.%d", path, (int)getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return false;
    const uint8_t *p = (const uint8_t *)data;
    size_t left = len;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w <= 0) {
            close(fd);
            unlink(tmp);
            return false;
        }
        p += (size_t)w;
        left -= (size_t)w;
    }
    (void)fchmod(fd, mode);
    close(fd);
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return false;
    }
    return true;
}

static void json_escape(const char *in, char *out, size_t cap) {
    if (cap == 0) return;
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 2 < cap; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            if (j + 3 >= cap) break;
            out[j++] = '\\';
            out[j++] = (char)c;
        } else if (c == '\n' || c == '\r' || c == '\t') {
            out[j++] = ' ';
        } else if (c >= 32 && c < 127) {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
}

static void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[in[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    if (!hex || strlen(hex) != out_len * 2) return false;
    for (size_t i = 0; i < out_len; i++) {
        char c1 = hex[i * 2];
        char c2 = hex[i * 2 + 1];
        int v1 = (c1 >= '0' && c1 <= '9') ? (c1 - '0') :
                 (c1 >= 'a' && c1 <= 'f') ? (c1 - 'a' + 10) :
                 (c1 >= 'A' && c1 <= 'F') ? (c1 - 'A' + 10) : -1;
        int v2 = (c2 >= '0' && c2 <= '9') ? (c2 - '0') :
                 (c2 >= 'a' && c2 <= 'f') ? (c2 - 'a' + 10) :
                 (c2 >= 'A' && c2 <= 'F') ? (c2 - 'A' + 10) : -1;
        if (v1 < 0 || v2 < 0) return false;
        out[i] = (uint8_t)((v1 << 4) | v2);
    }
    return true;
}

static bool sha256_file(const char *path, uint8_t out_hash[32]) {
    static EVP_MD_CTX *cached_ctx = NULL;
    static const EVP_MD *cached_md = NULL;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    if (!cached_md) cached_md = EVP_sha256();
    if (!cached_ctx) cached_ctx = EVP_MD_CTX_new();
    if (!cached_ctx || !cached_md) {
        close(fd);
        return false;
    }
    if (EVP_DigestInit_ex(cached_ctx, cached_md, NULL) != 1) {
        close(fd);
        return false;
    }
    uint8_t buf[16384];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (EVP_DigestUpdate(cached_ctx, buf, (size_t)n) != 1) {
            close(fd);
            return false;
        }
    }
    close(fd);
    unsigned int md_len = 0;
    return (n >= 0 && EVP_DigestFinal_ex(cached_ctx, out_hash, &md_len) == 1 && md_len == 32);
}

static void mkdir_p(const char *dir, mode_t mode, uid_t uid, gid_t gid) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%.1000s", dir);
    size_t len = strlen(tmp);
    if (len == 0) return;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) == 0 && uid != (uid_t)-1) {
                if (chown(tmp, uid, gid) != 0) { /* ignore */ }
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) == 0 && uid != (uid_t)-1) {
        if (chown(tmp, uid, gid) != 0) { /* ignore */ }
    }
}

static int count_quarantine_files(void) {
    DIR *d = opendir(g_quarantine_dir);
    if (!d) return 0;
    int cnt = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t l = strlen(de->d_name);
        if (l > 5 && strcmp(de->d_name + l - 5, ".qenc") == 0) cnt++;
    }
    closedir(d);
    return cnt;
}

static void refresh_status_shm(bool daemon_active) {
    int qcnt = count_quarantine_files();
    uint32_t rcnt = g_rules_shm ? g_rules_shm->count : 0;
    uint32_t fast_blk = g_rules_shm ? g_rules_shm->total_blocks : g_immune_fast_blocks;
    char inc_esc[320];
    json_escape(g_last_incident, inc_esc, sizeof(inc_esc));

    char json[1536];
    int len = snprintf(
        json, sizeof(json),
        "{\"active\":%s,\"mode\":\"%s\",\"version\":\"%s\",\"pid\":%d,\"uptime_s\":%" PRIu64 ","
        "\"quarantined\":%d,\"immune_rules\":%u,\"incidents_total\":%u,"
        "\"canary_blocks\":%u,\"immune_fast_blocks\":%u,\"files_restored\":%u,"
        "\"last_freeze_us\":%" PRIu64 ",\"last_incident\":\"%s\",\"ts\":%" PRIu64 "}\n",
        daemon_active ? "true" : "false",
        g_shadow_mode ? "shadow" : "enforce",
        HSHIELD_VERSION,
        (int)getpid(),
        g_boot_ts ? ((uint64_t)time(NULL) - g_boot_ts) : (uint64_t)0,
        qcnt,
        rcnt,
        g_incidents_total,
        g_canary_blocks,
        fast_blk,
        g_files_restored,
        g_last_freeze_us,
        inc_esc,
        (uint64_t)time(NULL)
    );
    if (len > 0) {
        (void)write_file_atomic(g_status_shm_path, json, (size_t)len, 0644);
    }
}

/* =========================================================================
 * Process Metadata & "Mutlak Guvenli Cekirdek" (Sacred Core) Verification
 * ========================================================================= */
static bool is_script_interpreter_exe(const char *exe, const char *comm) {
    const char *base = strrchr(exe, '/');
    base = base ? (base + 1) : comm;
    return (strncmp(base, "python", 6) == 0 ||
            strncmp(base, "pypy", 4) == 0 ||
            strcmp(base, "bash") == 0 ||
            strcmp(base, "sh") == 0 ||
            strcmp(base, "dash") == 0 ||
            strcmp(base, "zsh") == 0 ||
            strcmp(base, "node") == 0 ||
            strcmp(base, "deno") == 0 ||
            strcmp(base, "bun") == 0 ||
            strcmp(base, "perl") == 0 ||
            strcmp(base, "ruby") == 0 ||
            strncmp(base, "php", 3) == 0 ||
            strncmp(base, "lua", 3) == 0);
}

static bool read_proc_meta(pid_t pid, ProcMeta *pm) {
    memset(pm, 0, sizeof(*pm));
    pm->pid = pid;
    pm->pgid = getpgid(pid);

    char p[128];
    snprintf(p, sizeof(p), "/proc/%d/exe", (int)pid);
    ssize_t rl = readlink(p, pm->exe, sizeof(pm->exe) - 1);
    if (rl > 0) pm->exe[rl] = '\0';

    snprintf(p, sizeof(p), "/proc/%d/cwd", (int)pid);
    rl = readlink(p, pm->cwd, sizeof(pm->cwd) - 1);
    if (rl > 0) pm->cwd[rl] = '\0';

    snprintf(p, sizeof(p), "/proc/%d/comm", (int)pid);
    if (read_file_fast(p, pm->comm, sizeof(pm->comm)) > 0) {
        size_t cl = strlen(pm->comm);
        while (cl > 0 && (pm->comm[cl - 1] == '\n' || pm->comm[cl - 1] == '\r')) pm->comm[--cl] = '\0';
    }

    snprintf(p, sizeof(p), "/proc/%d/cmdline", (int)pid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char raw[1024];
        ssize_t n = read(fd, raw, sizeof(raw) - 1);
        close(fd);
        if (n > 0) {
            raw[n] = '\0';
            /*
             * Populate script_arg ONLY when exe is an actual script interpreter.
             * Non-interpreters (timeout, rm, cp, cat, pgrep, zathura, spectacle, etc.)
             * never execute argv[k] as interpreted code.
             */
            bool is_interp = is_script_interpreter_exe(pm->exe, pm->comm);
            bool stop_script_scan = !is_interp;
            bool skip_next_opt_arg = false;
            int arg_idx = 0;
            size_t i = 0;
            while (i < (size_t)n) {
                const char *tok = raw + i;
                size_t tl = strlen(tok);
                if (!stop_script_scan && arg_idx >= 1) {
                    if (skip_next_opt_arg) {
                        skip_next_opt_arg = false;
                    } else if (strcmp(tok, "-c") == 0 || strcmp(tok, "-m") == 0 ||
                               strcmp(tok, "-e") == 0 || strcmp(tok, "-") == 0) {
                        /* Inline script / module / stdin: no script file argument follows */
                        stop_script_scan = true;
                    } else if (strcmp(tok, "-W") == 0 || strcmp(tok, "-X") == 0 ||
                               strcmp(tok, "--check-hash-based-pycs") == 0) {
                        skip_next_opt_arg = true;
                    } else if (tok[0] != '-') {
                        char cand[512] = {0};
                        if (tok[0] == '/') {
                            snprintf(cand, sizeof(cand), "%.500s", tok);
                        } else if (pm->cwd[0]) {
                            snprintf(cand, sizeof(cand), "%.240s/%.250s", pm->cwd, tok);
                        }
                        struct stat st;
                        if (cand[0] && stat(cand, &st) == 0 && S_ISREG(st.st_mode)) {
                            snprintf(pm->script_arg, sizeof(pm->script_arg), "%.500s", cand);
                        }
                        stop_script_scan = true;
                    }
                }
                arg_idx++;
                i += tl + 1;
            }
            for (ssize_t k = 0; k < n; k++) {
                if (raw[k] == '\0') raw[k] = ' ';
            }
            while (n > 0 && raw[n - 1] == ' ') raw[--n] = '\0';
            snprintf(pm->cmdline, sizeof(pm->cmdline), "%.1020s", raw);
        }
    }

    snprintf(p, sizeof(p), "/proc/%d/status", (int)pid);
    char st[2048];
    if (read_file_fast(p, st, sizeof(st)) > 0) {
        char *pp = strstr(st, "\nPPid:\t");
        if (pp) pm->ppid = (pid_t)atoi(pp + 7);
        char *up = strstr(st, "\nUid:\t");
        if (up) pm->uid = (uid_t)strtoul(up + 6, NULL, 10);
    } else if (pm->exe[0] == '\0' && pm->comm[0] == '\0') {
        return false;
    }
    return true;
}

/*
 * Mutlak Guvenli Cekirdek (Sacred Core):
 * NEVER freeze, kill, or interrupt Brain (CNHM), ZeroMemory (zmd), Chrome,
 * active AI agents (Claude Code, agy CLI, Codex), hephaestus-core binaries,
 * or core OS/KDE/systemd infrastructure!
 */
static bool is_sacred_core(const ProcMeta *pm) {
    if (pm->pid <= 2 || pm->pid == getpid() || pm->ppid == getpid()) return true;
    if (pm->exe[0] == '\0' && pm->cmdline[0] == '\0') return true; /* Kernel thread */

    /* Never exempt a fileless memfd process as Sacred Core */
    if (strncmp(pm->exe, "/memfd:", 7) == 0 || strstr(pm->exe, "/memfd:") != NULL) {
        return false;
    }

    /* Hephaestus Core Binaries & Python/Shell Wrappers (`hzm`, `hvault`, `hrollback`, `hephaestus-mcp`) */
    if (strncmp(pm->exe, "/usr/local/bin/h", 16) == 0 ||
        strncmp(pm->exe, "/usr/local/bin/h", 25) == 0 ||
        strncmp(pm->script_arg, "/usr/local/bin/h", 16) == 0 ||
        strncmp(pm->script_arg, "/usr/local/bin/h", 25) == 0) {
        return true;
    }

    /* Brain (CNHM) & brain-venv */
    if (strstr(pm->exe, "/Desktop/Brain") || strstr(pm->cwd, "/Desktop/Brain") ||
        strstr(pm->cmdline, "/Desktop/Brain") || strstr(pm->exe, "/brain-venv/")) {
        /* Only exempt if not running a scratch simulation payload in /dev/shm */
        if (!strstr(pm->cmdline, "/dev/shm/") && !strstr(pm->cmdline, "/tmp/")) {
            return true;
        }
    }

    /* ZeroMemory (zmd) */
    if (strcmp(pm->comm, "zmd") == 0 || strstr(pm->exe, "/zmd") ||
        strstr(pm->cmdline, "ZeroMemory") || strstr(pm->cwd, "ZeroMemory")) {
        return true;
    }

    /* Google Chrome */
    if (strncmp(pm->exe, "/opt/google/chrome/", 19) == 0) return true;

    /* Active AI Agent Binaries (Claude Code, Antigravity agy CLI, Codex) */
    if (strstr(pm->exe, "/.local/share/claude/") ||
        strstr(pm->exe, "antigravity") ||
        strstr(pm->exe, "/codex") ||
        strstr(pm->exe, "/opencodex") ||
        strcmp(pm->comm, "claude") == 0 ||
        strcmp(pm->comm, "agy") == 0 ||
        strcmp(pm->comm, "codex") == 0) {
        return true;
    }

    /* Hephaestus Core Binaries */
    if (strncmp(pm->exe, "/usr/local/bin/h", 16) == 0 ||
        strncmp(pm->exe, "/usr/local/bin/h", 25) == 0 ||
        (strstr(pm->cmdline, "/usr/local/bin/h") && !strstr(pm->cmdline, "/dev/shm/")) ||
        (strstr(pm->cmdline, "/usr/local/bin/h") && !strstr(pm->cmdline, "/dev/shm/"))) {
        return true;
    }

    /* Core Linux / KDE / Docker / Toolchain Infrastructure */
    if (strncmp(pm->exe, "/usr/lib/systemd/", 17) == 0 ||
        strcmp(pm->comm, "systemd") == 0 ||
        strcmp(pm->comm, "dbus-daemon") == 0 ||
        strcmp(pm->comm, "dbus-broker") == 0 ||
        strcmp(pm->comm, "kwin_wayland") == 0 ||
        strcmp(pm->comm, "plasmashell") == 0 ||
        strcmp(pm->comm, "Xwayland") == 0 ||
        strcmp(pm->comm, "pipewire") == 0 ||
        strcmp(pm->comm, "wireplumber") == 0 ||
        strcmp(pm->comm, "dockerd") == 0 ||
        strcmp(pm->comm, "containerd") == 0 ||
        strcmp(pm->comm, "tailscaled") == 0 ||
        strcmp(pm->comm, "sshd") == 0 ||
        strcmp(pm->comm, "snapperd") == 0 ||
        strcmp(pm->exe, "/usr/bin/btrfs") == 0 ||
        strcmp(pm->exe, "/usr/bin/snapper") == 0 ||
        strcmp(pm->exe, "/usr/bin/nft") == 0 ||
        strcmp(pm->exe, "/usr/bin/sudo") == 0 ||
        strcmp(pm->exe, "/usr/bin/git") == 0 ||
        strcmp(pm->exe, "/usr/bin/gcc") == 0 ||
        strcmp(pm->exe, "/usr/bin/make") == 0) {
        return true;
    }

    return false;
}

/* =========================================================================
 * Sub-0.1ms Task-Scoped Amber Freeze (`SIGSTOP`) & Eradication (`SIGKILL`)
 * ========================================================================= */
/*
 * Attribution invariant: target ONLY the offending process `pm->pid`.
 * Never send group-wide `kill(-pgid, ...)` or parent/sibling signals, so
 * wrappers like `timeout`, `nohup`, or shells are never collateral victims.
 * Any malicious child `execve` is independently caught via `CN_PROC`.
 */
static uint64_t amber_freeze_task(const ProcMeta *pm) {
    uint64_t t0 = mono_ns();
    if (!g_shadow_mode && pm->pid > 2 && !is_sacred_core(pm)) {
        (void)kill(pm->pid, SIGSTOP);
    }
    uint64_t dt_us = (mono_ns() - t0) / 1000ULL;
    if (dt_us == 0) dt_us = 1;
    return dt_us;
}

static void eradicate_task(const ProcMeta *pm) {
    if (!g_shadow_mode && pm->pid > 2 && !is_sacred_core(pm)) {
        (void)kill(pm->pid, SIGKILL);
    }
}

/* =========================================================================
 * Compiled Binary Immune Rule Table (`/dev/shm/hephaestus_shield_rules.bin`)
 * ========================================================================= */
static bool init_rules_shm(bool create_rw) {
    int flags = create_rw ? (O_RDWR | O_CREAT | O_CLOEXEC) : (O_RDONLY | O_CLOEXEC);
    g_rules_fd = open(g_rules_shm_path, flags, 0644);
    if (g_rules_fd < 0) return false;

    if (create_rw) {
        struct stat st;
        bool fresh = (fstat(g_rules_fd, &st) != 0 || (size_t)st.st_size != sizeof(ShieldRuleTable));
        if (ftruncate(g_rules_fd, (off_t)sizeof(ShieldRuleTable)) != 0) {
            close(g_rules_fd);
            g_rules_fd = -1;
            return false;
        }
        (void)fchmod(g_rules_fd, 0644);
        void *map = mmap(NULL, sizeof(ShieldRuleTable), PROT_READ | PROT_WRITE, MAP_SHARED, g_rules_fd, 0);
        if (map == MAP_FAILED) {
            close(g_rules_fd);
            g_rules_fd = -1;
            return false;
        }
        g_rules_shm = (ShieldRuleTable *)map;
        if (fresh || g_rules_shm->magic != HSHIELD_RULE_MAGIC) {
            memset(g_rules_shm, 0, sizeof(ShieldRuleTable));
            g_rules_shm->magic = HSHIELD_RULE_MAGIC;
            g_rules_shm->version = HSHIELD_RULE_VERSION;
        }
    } else {
        struct stat st;
        if (fstat(g_rules_fd, &st) != 0 || (size_t)st.st_size < sizeof(ShieldRuleTable)) {
            close(g_rules_fd);
            g_rules_fd = -1;
            return false;
        }
        void *map = mmap(NULL, sizeof(ShieldRuleTable), PROT_READ, MAP_SHARED, g_rules_fd, 0);
        if (map == MAP_FAILED) {
            close(g_rules_fd);
            g_rules_fd = -1;
            return false;
        }
        g_rules_shm = (ShieldRuleTable *)map;
    }
    return true;
}

static void save_rules_json_snapshot(void) {
    if (!g_rules_shm || g_shadow_mode) return;
    mkdir_p(ETC_DIR_PATH, 0755, 0, 0);
    char tmp_json[1024];
    snprintf(tmp_json, sizeof(tmp_json), "%.980s.tmp", g_rules_json_path);
    FILE *fp = fopen(tmp_json, "we");
    if (!fp) return;
    fprintf(fp, "{\n  \"version\": %u,\n  \"count\": %u,\n  \"rules\": [\n",
            g_rules_shm->version, g_rules_shm->count);
    for (uint32_t i = 0; i < g_rules_shm->count && i < HSHIELD_MAX_RULES; i++) {
        const ShieldRuleBin *r = &g_rules_shm->rules[i];
        char hex[65] = "";
        if (r->has_sha256) bytes_to_hex(r->sha256, 32, hex);
        char pat_e[260], rsn_e[200];
        json_escape(r->pattern, pat_e, sizeof(pat_e));
        json_escape(r->reason, rsn_e, sizeof(rsn_e));
        fprintf(fp,
                "    {\"sha256\":\"%s\",\"pattern\":\"%s\",\"reason\":\"%s\","
                "\"hits\":%u,\"created_ts\":%" PRIu64 "}%s\n",
                hex, pat_e, rsn_e, r->hit_count, r->created_ts,
                (i + 1 < g_rules_shm->count) ? "," : "");
    }
    fprintf(fp, "  ]\n}\n");
    fclose(fp);
    (void)chmod(tmp_json, 0644);
    (void)rename(tmp_json, g_rules_json_path);
}

static void load_rules_json_into_shm(void) {
    if (!g_rules_shm || g_rules_shm->count > 0) return;
    FILE *fp = fopen(g_rules_json_path, "re");
    if (!fp) return;
    char line[1024];
    while (fgets(line, sizeof(line), fp) && g_rules_shm->count < HSHIELD_MAX_RULES) {
        char *sp = strstr(line, "\"sha256\":\"");
        char *pp = strstr(line, "\"pattern\":\"");
        char *rp = strstr(line, "\"reason\":\"");
        if (!sp && !pp) continue;
        ShieldRuleBin r;
        memset(&r, 0, sizeof(r));
        r.severity = 2;
        r.created_ts = (uint64_t)time(NULL);
        if (sp) {
            sp += 10;
            char hex[65] = {0};
            size_t k = 0;
            while (sp[k] && sp[k] != '"' && k < 64) { hex[k] = sp[k]; k++; }
            if (k == 64 && hex_to_bytes(hex, r.sha256, 32)) r.has_sha256 = 1;
        }
        if (pp) {
            pp += 11;
            size_t k = 0;
            while (pp[k] && pp[k] != '"' && k + 1 < sizeof(r.pattern)) {
                r.pattern[k] = pp[k];
                k++;
            }
            if (k > 0) r.has_pattern = 1;
        }
        if (rp) {
            rp += 10;
            size_t k = 0;
            while (rp[k] && rp[k] != '"' && k + 1 < sizeof(r.reason)) {
                r.reason[k] = rp[k];
                k++;
            }
        }
        if (r.has_sha256 || r.has_pattern) {
            g_rules_shm->rules[g_rules_shm->count++] = r;
        }
    }
    fclose(fp);
}

static bool add_immune_rule(const uint8_t *sha256_opt, const char *pattern_opt, const char *reason) {
    if (!g_rules_shm) return false;
    bool has_sha = (sha256_opt != NULL);
    bool has_pat = (pattern_opt != NULL && pattern_opt[0] != '\0');
    if (!has_sha && !has_pat) return false;

    /* Deduplicate existing rules */
    for (uint32_t i = 0; i < g_rules_shm->count && i < HSHIELD_MAX_RULES; i++) {
        ShieldRuleBin *ex = &g_rules_shm->rules[i];
        if (has_sha && ex->has_sha256 && memcmp(ex->sha256, sha256_opt, 32) == 0) {
            return true;
        }
        if (!has_sha && has_pat && ex->has_pattern && strcmp(ex->pattern, pattern_opt) == 0) {
            return true;
        }
    }
    if (g_rules_shm->count >= HSHIELD_MAX_RULES) return false;

    ShieldRuleBin *nr = &g_rules_shm->rules[g_rules_shm->count];
    memset(nr, 0, sizeof(*nr));
    nr->severity = 2;
    nr->created_ts = (uint64_t)time(NULL);
    if (has_sha) {
        memcpy(nr->sha256, sha256_opt, 32);
        nr->has_sha256 = 1;
    }
    if (has_pat) {
        snprintf(nr->pattern, sizeof(nr->pattern), "%.124s", pattern_opt);
        nr->has_pattern = 1;
    }
    snprintf(nr->reason, sizeof(nr->reason), "%.92s", reason ? reason : "autonomous-antibody");
    g_rules_shm->count++;
    save_rules_json_snapshot();
    return true;
}

static void ingest_antibody_zeromemory_async(const char *title, const char *body) {
    pid_t pid = fork();
    if (pid == 0) {
        /* Drop to unprivileged target user & clear all capabilities so child zmd/hzm is 100% dumpable/inspectable */
        if (setgid(USER_GID) != 0 || setuid(USER_UID) != 0) {
            _exit(1);
        }
        (void)prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
        struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
        struct __user_cap_data_struct data[2];
        memset(data, 0, sizeof(data));
        (void)syscall(SYS_capset, &hdr, data);
        (void)prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
        int lfd = open("/dev/shm/hshield_zm_ingest.lock", O_CREAT | O_RDWR | O_CLOEXEC, 0600);
        if (lfd >= 0 && flock(lfd, LOCK_EX | LOCK_NB) != 0) {
            _exit(0); /* Another antibody ingest is already in flight; shield_rules.bin has all rules! */
        }
        setenv("HOME", USER_HOME, 1);
        setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1);
        setenv("TMPDIR", "/tmp", 1);
        setenv("SQLITE_TMPDIR", "/tmp", 1);
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            (void)dup2(devnull, STDIN_FILENO);
            (void)dup2(devnull, STDOUT_FILENO);
            (void)dup2(devnull, STDERR_FILENO);
            if (devnull > 2) close(devnull);
        }
        execl("/usr/local/bin/hzm", "hzm", "ingest",
              "-k", "lesson", "--importance", "0.86",
              "-p", "hephaestus-core",
              "-t", title, "-b", body, (char *)NULL);
        _exit(0);
    }
}

/* =========================================================================
 * AES-256-GCM Quarantine Encryption & `nftables` C2 Block + `hrollback`
 * ========================================================================= */
static bool ensure_quarantine_key(void) {
    if (g_qkey_loaded) return true;
    mkdir_p(ETC_DIR_PATH, 0755, 0, 0);
    int fd = open(ETC_QKEY_PATH, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, g_qkey, 32);
        close(fd);
        if (n == 32) {
            g_qkey_loaded = true;
            return true;
        }
    }
    if (RAND_bytes(g_qkey, 32) != 1) return false;
    if (!write_file_atomic(ETC_QKEY_PATH, g_qkey, 32, 0600)) return false;
    g_qkey_loaded = true;
    return true;
}

static bool quarantine_encrypt_file(const char *src_path, const char *qenc_out, uint8_t sha256_out[32]) {
    if (!ensure_quarantine_key()) return false;
    if (!sha256_file(src_path, sha256_out)) return false;

    int in_fd = open(src_path, O_RDONLY | O_CLOEXEC);
    if (in_fd < 0) return false;

    int out_fd = open(qenc_out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0400);
    if (out_fd < 0) {
        close(in_fd);
        return false;
    }

    uint8_t iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        close(in_fd);
        close(out_fd);
        unlink(qenc_out);
        return false;
    }

    /* Header: "HQE1" (4B) + 12B IV + ciphertext + 16B GCM Tag */
    if (write(out_fd, "HQE1", 4) != 4 || write(out_fd, iv, 12) != 12) {
        close(in_fd);
        close(out_fd);
        unlink(qenc_out);
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, g_qkey, iv) != 1) {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        close(in_fd);
        close(out_fd);
        unlink(qenc_out);
        return false;
    }

    uint8_t inbuf[16384], outbuf[16416];
    ssize_t n;
    int outlen = 0;
    size_t total = 0;
    while ((n = read(in_fd, inbuf, sizeof(inbuf))) > 0 && total < (64ULL * 1024ULL * 1024ULL)) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)n) != 1) break;
        if (outlen > 0 && write(out_fd, outbuf, (size_t)outlen) != outlen) break;
        total += (size_t)n;
    }
    close(in_fd);

    uint8_t tag[16];
    bool ok = (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) == 1);
    if (ok && outlen > 0) {
        if (write(out_fd, outbuf, (size_t)outlen) != outlen) ok = false;
    }
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1) {
        if (write(out_fd, tag, 16) != 16) ok = false;
    } else {
        ok = false;
    }
    EVP_CIPHER_CTX_free(ctx);
    (void)fchmod(out_fd, 0400);
    if (fchown(out_fd, USER_UID, USER_GID) != 0) { /* ignore */ }
    close(out_fd);
    if (!ok) unlink(qenc_out);
    return ok;
}

static int run_cmd_quiet(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) {
            (void)dup2(dn, STDIN_FILENO);
            (void)dup2(dn, STDOUT_FILENO);
            (void)dup2(dn, STDERR_FILENO);
            if (dn > 2) close(dn);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void init_nftables_shield(void) {
    char *cmd1[] = {"/usr/bin/nft", "add", "table", "inet", "hephaestus_shield", NULL};
    (void)run_cmd_quiet(cmd1);
    char *cmd2[] = {"/usr/bin/nft", "add", "set", "inet", "hephaestus_shield", "c2_block_v4",
                    "{ type ipv4_addr ; flags interval ; }", NULL};
    (void)run_cmd_quiet(cmd2);
    char *cmd3[] = {"/usr/bin/nft", "add", "chain", "inet", "hephaestus_shield", "output",
                    "{ type filter hook output priority 0 ; policy accept ; }", NULL};
    (void)run_cmd_quiet(cmd3);
    /* Flush chain first so reload doesn't stack duplicate rules */
    char *cmd4[] = {"/usr/bin/nft", "flush", "chain", "inet", "hephaestus_shield", "output", NULL};
    (void)run_cmd_quiet(cmd4);
    char *cmd5[] = {"/usr/bin/nft", "add", "rule", "inet", "hephaestus_shield", "output",
                    "ip", "daddr", "@c2_block_v4", "drop", NULL};
    (void)run_cmd_quiet(cmd5);
}

static bool is_private_or_safe_ipv4(uint32_t ip_host) {
    uint8_t a = (uint8_t)((ip_host >> 24) & 0xFF);
    uint8_t b = (uint8_t)((ip_host >> 16) & 0xFF);
    if (a == 0 || a == 127 || a == 10) return true;
    if (a == 192 && b == 168) return true;
    if (a == 172 && (b >= 16 && b <= 31)) return true;
    if (a == 100 && (b >= 64 && b <= 127)) return true; /* Tailscale CGNAT */
    if (ip_host == 0x01010101U || ip_host == 0x08080808U) return true; /* DNS */
    return false;
}

static void nft_block_ipv4(const char *ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) return;
    if (is_private_or_safe_ipv4(ntohl(addr.s_addr))) return;
    char elem[64];
    snprintf(elem, sizeof(elem), "{ %.32s }", ip_str);
    char *cmd[] = {"/usr/bin/nft", "add", "element", "inet", "hephaestus_shield", "c2_block_v4", elem, NULL};
    (void)run_cmd_quiet(cmd);
}

static int cmp_int_desc(const void *a, const void *b) {
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    return (ib > ia) - (ib < ia);
}

static bool files_equal_fast(const char *p1, const char *p2) {
    struct stat s1, s2;
    if (stat(p1, &s1) != 0 || stat(p2, &s2) != 0) return false;
    if (s1.st_size != s2.st_size) return false;
    int f1 = open(p1, O_RDONLY | O_CLOEXEC);
    if (f1 < 0) return false;
    int f2 = open(p2, O_RDONLY | O_CLOEXEC);
    if (f2 < 0) { close(f1); return false; }
    uint8_t b1[8192], b2[8192];
    bool same = true;
    for (;;) {
        ssize_t n1 = read(f1, b1, sizeof(b1));
        ssize_t n2 = read(f2, b2, sizeof(b2));
        if (n1 != n2) { same = false; break; }
        if (n1 <= 0) break;
        if (memcmp(b1, b2, (size_t)n1) != 0) { same = false; break; }
    }
    close(f1);
    close(f2);
    return same;
}

static bool is_sacred_data_path(const char *p) {
    return (strncmp(p, "/opt/protected-workloads/", 27) == 0 ||
            strncmp(p, "/var/lib/protected-memory/", 20) == 0 ||
            strncmp(p, "/var/lib/protected-index", 36) == 0 ||
            strncmp(p, "/etc/hshield/protected-browser/", 35) == 0);
}

/*
 * Native C11 Kernel Btrfs CoW Single-File Restore (`ioctl(FICLONE)`):
 * Restores a corrupted/deleted file from the latest Snapper snapshot in ~150 us (0.15 ms)!
 */
static bool restore_file_cow_fast(const char *target_path, uint64_t *elapsed_us_out) {
    uint64_t t0 = mono_ns();
    if (!target_path || target_path[0] != '/' || is_sacred_data_path(target_path)) return false;

    const char *snap_base = "/.snapshots";
    const char *rel = target_path + 1;
    if (strncmp(target_path, "/home/", 6) == 0) {
        snap_base = "/home/.snapshots";
        rel = target_path + 6;
    }

    DIR *d = opendir(snap_base);
    if (!d) return false;
    int snaps[512];
    int nsnaps = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && nsnaps < 512) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        bool all_num = true;
        for (size_t k = 0; de->d_name[k]; k++) {
            if (!isdigit((unsigned char)de->d_name[k])) { all_num = false; break; }
        }
        if (all_num) snaps[nsnaps++] = atoi(de->d_name);
    }
    closedir(d);
    if (nsnaps == 0) return false;
    qsort(snaps, (size_t)nsnaps, sizeof(int), cmp_int_desc);

    char chosen_src[1024] = {0};
    struct stat chosen_st;
    memset(&chosen_st, 0, sizeof(chosen_st));
    for (int i = 0; i < nsnaps && i < 16; i++) {
        char cand[1024];
        snprintf(cand, sizeof(cand), "%s/%d/snapshot/%.850s", snap_base, snaps[i], rel);
        struct stat cst;
        if (stat(cand, &cst) == 0 && S_ISREG(cst.st_mode)) {
            if (!chosen_src[0]) {
                snprintf(chosen_src, sizeof(chosen_src), "%s", cand);
                chosen_st = cst;
            }
            if (!files_equal_fast(cand, target_path)) {
                snprintf(chosen_src, sizeof(chosen_src), "%s", cand);
                chosen_st = cst;
                break;
            }
        }
    }
    if (!chosen_src[0]) return false;

    int sfd = open(chosen_src, O_RDONLY | O_CLOEXEC);
    if (sfd < 0) return false;

    char tmp_dst[1080];
    snprintf(tmp_dst, sizeof(tmp_dst), "%.1024s.hshield_cow.%d", target_path, (int)getpid());
    int dfd = open(tmp_dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, chosen_st.st_mode & 0777);
    if (dfd < 0) {
        close(sfd);
        return false;
    }

    bool cloned = (ioctl(dfd, FICLONE, sfd) == 0);
    if (!cloned) {
        uint8_t buf[16384];
        ssize_t n;
        cloned = true;
        while ((n = read(sfd, buf, sizeof(buf))) > 0) {
            if (write(dfd, buf, (size_t)n) != n) { cloned = false; break; }
        }
    }
    (void)fchmod(dfd, chosen_st.st_mode & 07777);
    if (fchown(dfd, chosen_st.st_uid, chosen_st.st_gid) != 0) { /* ignore */ }
    struct timespec times[2] = { chosen_st.st_atim, chosen_st.st_mtim };
    (void)futimens(dfd, times);
    close(dfd);
    close(sfd);

    if (!cloned || rename(tmp_dst, target_path) != 0) {
        unlink(tmp_dst);
        return false;
    }

    uint64_t dt = (mono_ns() - t0) / 1000ULL;
    if (dt == 0) dt = 1;
    if (elapsed_us_out) *elapsed_us_out = dt;
    g_files_restored++;
    return true;
}

/* =========================================================================
 * Socket / FD / Memory Inspection Helpers
 * ========================================================================= */
static bool lookup_tcp_remote_by_inode(unsigned long sock_ino, char *ip_out, size_t ip_cap, uint16_t *port_out) {
    FILE *fp = fopen("/proc/net/tcp", "re");
    if (!fp) return false;
    char line[512];
    bool found = false;
    if (!fgets(line, sizeof(line), fp)) { /* header */
        fclose(fp);
        return false;
    }
    while (fgets(line, sizeof(line), fp)) {
        unsigned int sl = 0, l_ip = 0, l_port = 0, r_ip = 0, r_port = 0, st = 0;
        unsigned long ino = 0;
        if (sscanf(line, " %u: %X:%X %X:%X %X %*X:%*X %*X:%*X %*X %*u %*u %lu",
                   &sl, &l_ip, &l_port, &r_ip, &r_port, &st, &ino) == 7) {
            if (ino == sock_ino && r_ip != 0) {
                struct in_addr in;
                in.s_addr = r_ip;
                inet_ntop(AF_INET, &in, ip_out, (socklen_t)ip_cap);
                if (port_out) *port_out = (uint16_t)r_port;
                found = true;
                break;
            }
        }
    }
    fclose(fp);
    return found;
}

static bool is_untrusted_origin_path(const char *p) {
    if (!p || !p[0]) return false;
    return (strncmp(p, "/dev/shm/", 9) == 0 ||
            strncmp(p, "/tmp/", 5) == 0 ||
            strncmp(p, "/var/tmp/", 9) == 0 ||
            strncmp(p, "/memfd:", 7) == 0 ||
            strstr(p, "/Downloads/") != NULL);
}

static bool check_suspicious_exec_indicators(const ProcMeta *pm, char *reason_out, size_t rcap) {
    /* 1. Fileless memfd execution (`memfd_create` + `fexecve`) */
    if (strncmp(pm->exe, "/memfd:", 7) == 0 || strstr(pm->exe, "/memfd:") != NULL) {
        snprintf(reason_out, rcap, "fileless_memfd_exec");
        return true;
    }

    /* 2. Cryptominers */
    if (strstr(pm->cmdline, "stratum+tcp://") || strstr(pm->cmdline, "stratum+ssl://") ||
        strcmp(pm->comm, "xmrig") == 0 || strstr(pm->cmdline, "cryptonight")) {
        snprintf(reason_out, rcap, "unauthorized_cryptominer");
        return true;
    }

    /* 3. Suspicious LD_PRELOAD injection in /proc/<pid>/environ */
    char epath[128], envbuf[4096];
    snprintf(epath, sizeof(epath), "/proc/%d/environ", (int)pm->pid);
    ssize_t en = read_file_fast(epath, envbuf, sizeof(envbuf));
    if (en > 0) {
        for (ssize_t i = 0; i < en; ) {
            const char *kv = envbuf + i;
            size_t kl = strlen(kv);
            if (strncmp(kv, "LD_PRELOAD=", 11) == 0) {
                const char *val = kv + 11;
                if (is_untrusted_origin_path(val) || strstr(val, "/.") != NULL) {
                    snprintf(reason_out, rcap, "ld_preload_injection");
                    return true;
                }
            }
            i += (ssize_t)kl + 1;
        }
    }

    /* 4. Reverse Shell (`fd 0` & `fd 1` redirected to non-loopback network socket on shell) */
    if (strcmp(pm->comm, "sh") == 0 || strcmp(pm->comm, "bash") == 0 ||
        strcmp(pm->comm, "dash") == 0 || strcmp(pm->comm, "zsh") == 0) {
        char fd0p[128], fd1p[128], l0[128] = {0}, l1[128] = {0};
        snprintf(fd0p, sizeof(fd0p), "/proc/%d/fd/0", (int)pm->pid);
        snprintf(fd1p, sizeof(fd1p), "/proc/%d/fd/1", (int)pm->pid);
        if (readlink(fd0p, l0, sizeof(l0) - 1) > 0 && readlink(fd1p, l1, sizeof(l1) - 1) > 0) {
            unsigned long ino = 0;
            if (strncmp(l0, "socket:[", 8) == 0 && strcmp(l0, l1) == 0 &&
                sscanf(l0, "socket:[%lu]", &ino) == 1) {
                char rip[64] = {0};
                uint16_t rport = 0;
                if (lookup_tcp_remote_by_inode(ino, rip, sizeof(rip), &rport) &&
                    strncmp(rip, "127.", 4) != 0) {
                    snprintf(reason_out, rcap, "reverse_shell_socket:%s:%u", rip, rport);
                    return true;
                }
            }
        }
    }

    return false;
}

/* =========================================================================
 * Mechanistic W+X / W->X + Execution-Locus Evidence Model (Zero Allowlists)
 * ========================================================================= */
typedef enum {
    CONF_NONE   = 0,
    CONF_MEDIUM = 1,
    CONF_HIGH   = 2
} ConfidenceTier;

typedef enum {
    DECISION_ALLOW          = 0,
    DECISION_FREEZE_CONTAIN = 1,
    DECISION_SIGKILL        = 2
} ResponseDecision;

typedef struct {
    ConfidenceTier   confidence;
    ResponseDecision decision;
    int              risk_score;
    uint64_t         vma_start;
    uint64_t         vma_end;
    char             vma_perms[8];
    char             vma_backing[64];
    char             vma_transition[32];
    char             exec_proof[64];
    uint64_t         exec_rip;
    uint64_t         freeze_us;
    char             reason[160];
    char             summary[512];
} WxAssessment;

#define MAX_FILE_X_VMAS 256
#define MAX_CAND_X_VMAS 32

typedef struct {
    uint64_t start;
    uint64_t end;
    char     perms[8];
    char     backing[64];
    bool     is_memfd;
    bool     is_rwx;
    bool     is_w_to_x;
    bool     was_prev_rw;
    bool     is_stack_or_heap;
    bool     is_benign_ffi;
    bool     is_alloc_pool;
    bool     has_entry_syscall_stub;
} CandVma;

static ssize_t read_proc_maps_full(pid_t pid, char *buf, size_t cap) {
    if (cap == 0) return -1;
    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/maps", (int)pid);
    int fd = open(mpath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        buf[0] = '\0';
        return -1;
    }
    size_t total = 0;
    while (total + 1 < cap) {
        ssize_t n = read(fd, buf + total, cap - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    close(fd);
    buf[total] = '\0';
    return (ssize_t)total;
}

static bool addr_in_ranges(uint64_t addr, const VmaRange *ranges, int count) {
    for (int i = 0; i < count; i++) {
        if (addr >= ranges[i].start && addr < ranges[i].end) return true;
    }
    return false;
}

static bool range_overlaps_prev_rw(uint64_t start, uint64_t end, const PendingInspect *slot) {
    if (!slot) return false;
    for (int i = 0; i < slot->prev_rw_cnt; i++) {
        if (start < slot->prev_rw[i].end && end > slot->prev_rw[i].start) return true;
    }
    return false;
}

/*
 * Verify whether an anonymous VMA is a structural FFI closure trampoline page:
 *   1. Empty dlmalloc closure pool (`prev_foot == 0` at +0x00 and <= 16 non-zero
 *      header bytes across the page -> zero executable instructions exist), OR
 *   2. Closure table (`prev_foot == 0` or static trampoline page) containing
 *      x86_64 indirect tail-jump thunks (`ff 25 <disp32>` or `movabs + jmp *reg`)
 *      whose 64-bit target address resolves into a persistent file-backed `r-xp`
 *      shared library VMA (`file_x`), with no raw `syscall` (`0f 05`) stub at base.
 */
static bool is_mechanistic_ffi_trampoline(const uint8_t *buf, size_t len, uint64_t vma_start,
                                          bool is_rwx, const VmaRange *file_x, int file_x_cnt) {
    if (len == 0 || len > 65536) return false;

    uint64_t first_qword = 0;
    if (len >= 8) memcpy(&first_qword, buf, 8);

    size_t nonzero = 0;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) nonzero++;
    }
    /* Unpopulated dlmalloc closure pool (only chunk size integers, 0 instructions) */
    if (first_qword == 0 && nonzero <= 16) {
        return true;
    }

    /*
     * For RWX closure pages, offset +0x00 is either dlmalloc/free-list `0`
     * OR slot #0 itself starting with an `endbr64; lea; jmp *[rip+disp]` (`f3 0f 1e fa`)
     * or direct `ff 25` / `49 ba` trampoline thunk.
     */
    bool entry_is_thunk = (len >= 16 &&
        ((buf[0] == 0xf3 && buf[1] == 0x0f && buf[2] == 0x1e && buf[3] == 0xfa) ||
         (buf[0] == 0xff && buf[1] == 0x25) ||
         (buf[0] == 0x49 && (buf[1] == 0xba || buf[1] == 0xbb))));
    if (is_rwx && first_qword != 0 && !entry_is_thunk) {
        return false;
    }

    int valid_trampolines = 0;
    for (size_t i = 0; i + 16 <= len; i++) {
        /* Pattern A: RIP-relative indirect tail-jump `ff 25 <disp32>` (libffi x86_64) */
        if (buf[i] == 0xff && buf[i + 1] == 0x25) {
            int32_t disp = 0;
            memcpy(&disp, buf + i + 2, 4);
            int64_t target_off = (int64_t)(i + 6) + (int64_t)disp;
            if (target_off >= 0 && (size_t)(target_off + 8) <= len) {
                uint64_t jmp_dst = 0;
                memcpy(&jmp_dst, buf + (size_t)target_off, 8);
                if (addr_in_ranges(jmp_dst, file_x, file_x_cnt)) {
                    valid_trampolines++;
                }
            }
        }
        /* Pattern B: `movabs $imm64, %r10/%r11` + `jmp *%r10/%r11` (cffi closure) */
        if (i + 13 <= len && (buf[i] == 0x49) && (buf[i + 1] == 0xba || buf[i + 1] == 0xbb)) {
            uint64_t imm = 0;
            memcpy(&imm, buf + i + 2, 8);
            if (addr_in_ranges(imm, file_x, file_x_cnt)) {
                for (size_t k = i + 10; k + 3 <= len && k <= i + 24; k++) {
                    if (buf[k] == 0x41 && buf[k + 1] == 0xff && (buf[k + 2] == 0xe2 || buf[k + 2] == 0xe3)) {
                        valid_trampolines++;
                        break;
                    }
                }
            }
        }
    }
    (void)vma_start;
    return (valid_trampolines > 0);
}

/* Verify if `ret_addr` inside `vma_buf` was pushed by a genuine x86_64 `call` instruction */
static bool is_preceded_by_x86_call(const uint8_t *vma_buf, size_t vma_len, uint64_t vma_start, uint64_t ret_addr) {
    if (ret_addr <= vma_start || (ret_addr - vma_start) > vma_len) return false;
    size_t off = (size_t)(ret_addr - vma_start);
    /* Direct near call: E8 rel32 (5 bytes) */
    if (off >= 5 && vma_buf[off - 5] == 0xe8) return true;
    /* Indirect register call: FF D0..D7 (2 bytes) or REX + FF D0..D7 (3 bytes) */
    if (off >= 2 && vma_buf[off - 2] == 0xff && (vma_buf[off - 1] >= 0xd0 && vma_buf[off - 1] <= 0xd7)) return true;
    if (off >= 3 && (vma_buf[off - 3] >= 0x40 && vma_buf[off - 3] <= 0x4f) &&
        vma_buf[off - 2] == 0xff && (vma_buf[off - 1] >= 0xd0 && vma_buf[off - 1] <= 0xd7)) return true;
    /* Indirect memory call: FF 14/15/50..57/90..97 */
    if (off >= 6 && vma_buf[off - 6] == 0xff && (vma_buf[off - 5] == 0x15 || (vma_buf[off - 5] & 0x38) == 0x10)) return true;
    if (off >= 3 && vma_buf[off - 3] == 0xff && (vma_buf[off - 2] & 0x38) == 0x10) return true;
    return false;
}

/* Parse `/proc/<pid>/task/<tid>/syscall` -> extracts syscall_nr (-1 if user-space stopped), rsp, rip */
static bool read_tid_syscall_locus(pid_t pid, pid_t tid, bool use_ptrace_if_running,
                                   long *sys_nr_out, uint64_t *rsp_out, uint64_t *rip_out) {
    *sys_nr_out = -2;
    *rsp_out = 0;
    *rip_out = 0;

    char spath[96], sbuf[256];
    snprintf(spath, sizeof(spath), "/proc/%d/task/%d/syscall", (int)pid, (int)tid);
    if (read_file_fast(spath, sbuf, sizeof(sbuf)) <= 0) return false;

    if (strncmp(sbuf, "running", 7) == 0) {
        if (!use_ptrace_if_running) return false;
        /* Non-destructive register sample via PTRACE_SEIZE + PTRACE_INTERRUPT */
        struct user_regs_struct regs;
        memset(&regs, 0, sizeof(regs));
        bool ok = false;
        if (ptrace(PTRACE_SEIZE, tid, NULL, NULL) == 0) {
            if (ptrace(PTRACE_INTERRUPT, tid, NULL, NULL) == 0) {
                int st = 0;
                if (waitpid(tid, &st, __WALL) == tid) {
                    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
                    if (ptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &iov) == 0) {
                        *sys_nr_out = -1;
                        *rsp_out = (uint64_t)regs.rsp;
                        *rip_out = (uint64_t)regs.rip;
                        ok = true;
                    }
                }
            }
            (void)ptrace(PTRACE_DETACH, tid, NULL, NULL);
        }
        return ok;
    }

    char *endp = NULL;
    long nr = strtol(sbuf, &endp, 10);
    if (endp == sbuf) return false;
    /* Last two hex tokens in `/proc/tid/syscall` are always `<rsp> <rip>` */
    uint64_t vals[9] = {0};
    int vcnt = 0;
    char *p = endp;
    while (*p && vcnt < 9) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (!*p) break;
        if (*p == '0' && (p[1] == 'x' || p[1] == 'X')) {
            vals[vcnt++] = strtoull(p, &p, 16);
        } else {
            while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
        }
    }
    if (vcnt >= 2) {
        *sys_nr_out = nr;
        *rsp_out = vals[vcnt - 2];
        *rip_out = vals[vcnt - 1];
        return true;
    }
    return false;
}

static bool check_single_tid_against_vmas(pid_t pid, pid_t tid, int mem_fd,
                                          const CandVma *cands, int cand_cnt,
                                          bool sample_running_via_ptrace,
                                          int *matched_cand_idx, char *proof_out, size_t pcap,
                                          uint64_t *rip_out, int *exec_score_out) {
    long sys_nr = -2;
    uint64_t rsp = 0, rip = 0;
    if (!read_tid_syscall_locus(pid, tid, sample_running_via_ptrace, &sys_nr, &rsp, &rip)) {
        return false;
    }

    /* 1. Direct RIP inside candidate non-FFI anonymous/memfd VMA */
    for (int i = 0; i < cand_cnt; i++) {
        if (cands[i].is_benign_ffi) continue;
        if (rip >= cands[i].start && rip < cands[i].end) {
            if (sys_nr >= 0) {
                *matched_cand_idx = i;
                *rip_out = rip;
                *exec_score_out = 80;
                snprintf(proof_out, pcap, "syscall_rip_in_anon_vma(nr=%ld,tid=%d)", sys_nr, (int)tid);
                return true;
            }
            if (cands[i].is_memfd || cands[i].is_stack_or_heap ||
                (cands[i].is_rwx && !cands[i].is_alloc_pool) ||
                cands[i].has_entry_syscall_stub) {
                *matched_cand_idx = i;
                *rip_out = rip;
                *exec_score_out = 60;
                snprintf(proof_out, pcap, "cpu_rip_in_anon_vma(tid=%d)", (int)tid);
                return true;
            }
        }
    }

    /* 2. Active x86_64 call return frame on thread stack `[rsp, rsp+1024)` pointing into raw W+X VMA */
    if (mem_fd >= 0 && rsp > 4096) {
        uint8_t stack_buf[1024];
        uint8_t vma_cache[8192];
        ssize_t sn = pread(mem_fd, stack_buf, sizeof(stack_buf), (off_t)rsp);
        if (sn >= 8) {
            for (ssize_t off = 0; off + 8 <= sn; off += 8) {
                uint64_t slot_val = 0;
                memcpy(&slot_val, stack_buf + off, 8);
                for (int i = 0; i < cand_cnt; i++) {
                    if (cands[i].is_benign_ffi || cands[i].is_alloc_pool) continue;
                    if (!cands[i].is_rwx && !cands[i].is_memfd && !cands[i].has_entry_syscall_stub) continue;
                    if (slot_val > cands[i].start && slot_val < cands[i].end) {
                        uint64_t base = (slot_val > cands[i].start + 16) ? (slot_val - 16) : cands[i].start;
                        size_t rlen = (size_t)(slot_val - base);
                        if (rlen > sizeof(vma_cache)) rlen = sizeof(vma_cache);
                        ssize_t vn = pread(mem_fd, vma_cache, rlen, (off_t)base);
                        if (vn > 0 && is_preceded_by_x86_call(vma_cache, (size_t)vn, base, slot_val)) {
                            *matched_cand_idx = i;
                            *rip_out = slot_val;
                            *exec_score_out = 60;
                            snprintf(proof_out, pcap, "stack_call_ret_in_anon_vma(tid=%d,sp+0x%zx)", (int)tid, (size_t)off);
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

static void inspect_threads_against_vmas(pid_t pid, int mem_fd, const CandVma *cands, int cand_cnt,
                                         bool sample_running_via_ptrace,
                                         int *matched_cand_idx, char *proof_out, size_t pcap,
                                         uint64_t *rip_out, int *exec_score_out) {
    *matched_cand_idx = -1;
    proof_out[0] = '\0';
    *rip_out = 0;
    *exec_score_out = 0;

    /* Zero-opendir fast path for main thread (`tid == pid`) */
    if (check_single_tid_against_vmas(pid, pid, mem_fd, cands, cand_cnt, sample_running_via_ptrace,
                                      matched_cand_idx, proof_out, pcap, rip_out, exec_score_out)) {
        return;
    }

    char tdir[64];
    snprintf(tdir, sizeof(tdir), "/proc/%d/task", (int)pid);
    DIR *d = opendir(tdir);
    if (!d) return;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        pid_t tid = (pid_t)atoi(de->d_name);
        if (tid == pid) continue; /* Already checked on fast path */
        if (check_single_tid_against_vmas(pid, tid, mem_fd, cands, cand_cnt, sample_running_via_ptrace,
                                          matched_cand_idx, proof_out, pcap, rip_out, exec_score_out)) {
            closedir(d);
            return;
        }
    }
    closedir(d);
}

static bool assess_wx_injection(const ProcMeta *pm, PendingInspect *slot, uint64_t t_detect_ns, WxAssessment *out) {
    memset(out, 0, sizeof(*out));
    if (is_sacred_core(pm)) return false;

    static char maps_buf[131072];
    if (read_proc_maps_full(pm->pid, maps_buf, sizeof(maps_buf)) <= 0) return false;

    VmaRange file_x[MAX_FILE_X_VMAS];
    int file_x_cnt = 0;
    VmaRange cur_rw[MAX_PREV_RW_VMAS];
    int cur_rw_cnt = 0;
    CandVma cands[MAX_CAND_X_VMAS];
    int cand_cnt = 0;

    char *savep = NULL;
    for (char *ln = strtok_r(maps_buf, "\n", &savep); ln; ln = strtok_r(NULL, "\n", &savep)) {
        unsigned long long s = 0, e = 0, off = 0, ino = 0;
        char perms[8] = {0}, dev[16] = {0}, path[256] = {0};
        int n = sscanf(ln, "%llx-%llx %7s %llx %15s %llu %255[^\n]",
                       &s, &e, perms, &off, dev, &ino, path);
        if (n < 6 || e <= s) continue;
        char *p_trim = path;
        while (*p_trim == ' ' || *p_trim == '\t') p_trim++;

        bool has_w = (perms[1] == 'w');
        bool has_x = (perms[2] == 'x');
        bool is_kernel_special = (strcmp(p_trim, "[vdso]") == 0 ||
                                  strcmp(p_trim, "[vsyscall]") == 0 ||
                                  strncmp(p_trim, "[vvar", 5) == 0);
        if (is_kernel_special) continue;

        bool is_memfd = (strstr(p_trim, "/memfd:") != NULL);
        bool is_deleted = (strstr(p_trim, "(deleted)") != NULL);

        if (ino != 0 && has_x && !is_memfd && !is_deleted) {
            if (file_x_cnt < MAX_FILE_X_VMAS) {
                file_x[file_x_cnt].start = (uint64_t)s;
                file_x[file_x_cnt].end   = (uint64_t)e;
                file_x_cnt++;
            }
            continue;
        }

        if (ino == 0 && has_w && !has_x && cur_rw_cnt < MAX_PREV_RW_VMAS) {
            cur_rw[cur_rw_cnt].start = (uint64_t)s;
            cur_rw[cur_rw_cnt].end   = (uint64_t)e;
            cur_rw_cnt++;
            continue;
        }

        if (has_x && (ino == 0 || is_memfd) && cand_cnt < MAX_CAND_X_VMAS) {
            CandVma *c = &cands[cand_cnt++];
            memset(c, 0, sizeof(*c));
            c->start = (uint64_t)s;
            c->end   = (uint64_t)e;
            snprintf(c->perms, sizeof(c->perms), "%.7s", perms);
            snprintf(c->backing, sizeof(c->backing), "%.60s",
                     p_trim[0] ? p_trim : "anon");
            c->is_memfd = is_memfd;
            c->is_rwx   = has_w && has_x;
            c->was_prev_rw = range_overlaps_prev_rw(c->start, c->end, slot);
            c->is_w_to_x = (!has_w && has_x && ino == 0) || c->was_prev_rw;
            c->is_stack_or_heap = (strcmp(p_trim, "[stack]") == 0 || strcmp(p_trim, "[heap]") == 0);
        }
    }

    if (slot) {
        slot->prev_rw_cnt = cur_rw_cnt;
        for (int i = 0; i < cur_rw_cnt; i++) slot->prev_rw[i] = cur_rw[i];
    }

    if (cand_cnt == 0) {
        /* Also keep secondary check for stealth io_uring + external non-loopback C2 */
        if (is_untrusted_origin_path(pm->exe) || is_untrusted_origin_path(pm->script_arg)) {
            char fdpath[128];
            snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd", (int)pm->pid);
            DIR *d = opendir(fdpath);
            if (d) {
                bool has_uring = false;
                char ext_ip[64] = {0};
                uint16_t ext_port = 0;
                struct dirent *de;
                while ((de = readdir(d)) != NULL) {
                    if (!isdigit((unsigned char)de->d_name[0])) continue;
                    char lp[256], target[256] = {0};
                    snprintf(lp, sizeof(lp), "/proc/%d/fd/%.32s", (int)pm->pid, de->d_name);
                    if (readlink(lp, target, sizeof(target) - 1) > 0) {
                        if (strstr(target, "[io_uring]")) has_uring = true;
                        unsigned long sino = 0;
                        if (sscanf(target, "socket:[%lu]", &sino) == 1) {
                            char rip[64] = {0};
                            uint16_t rp = 0;
                            if (lookup_tcp_remote_by_inode(sino, rip, sizeof(rip), &rp) &&
                                strncmp(rip, "127.", 4) != 0) {
                                snprintf(ext_ip, sizeof(ext_ip), "%.60s", rip);
                                ext_port = rp;
                            }
                        }
                    }
                }
                closedir(d);
                if (has_uring && ext_ip[0] != '\0') {
                    out->confidence = CONF_HIGH;
                    out->decision   = DECISION_SIGKILL;
                    out->risk_score = 95;
                    (void)amber_freeze_task(pm);
                    out->freeze_us  = (mono_ns() - t_detect_ns) / 1000ULL;
                    if (out->freeze_us == 0) out->freeze_us = 1;
                    snprintf(out->reason, sizeof(out->reason), "stealth_io_uring_c2:%s:%u", ext_ip, ext_port);
                    snprintf(out->summary, sizeof(out->summary), "io_uring+ext_c2=%s:%u", ext_ip, ext_port);
                    return true;
                }
            }
        }
        return false;
    }

    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)pm->pid);
    int mem_fd = open(mem_path, O_RDONLY | O_CLOEXEC);

    uint8_t page_buf[4096];
    int best_idx = -1;
    int best_vma_score = 0;

    for (int i = 0; i < cand_cnt; i++) {
        CandVma *c = &cands[i];
        size_t vlen = (size_t)(c->end - c->start);
        size_t rlen = vlen < sizeof(page_buf) ? vlen : sizeof(page_buf);
        ssize_t got = (mem_fd >= 0) ? pread(mem_fd, page_buf, rlen, (off_t)c->start) : -1;

        if (got > 0 && !c->is_memfd && !c->is_stack_or_heap) {
            c->is_benign_ffi = is_mechanistic_ffi_trampoline(
                page_buf, (size_t)got, c->start, c->is_rwx, file_x, file_x_cnt);
            if (c->is_benign_ffi) continue;

            /*
             * Check allocator-headed JIT pool:
             *  - 32 zero-bytes fragment header (`sljit_memory_fragment` >= 64 KiB), OR
             *  - Multi-MiB (>= 4 MiB, 256 KiB-aligned) structured JIT CodeRange (`MemoryChunk`
             *    header where bytes[16..31] == 0 and offset 0 is not an ELF header).
             */
            bool zero32 = ((size_t)got >= 32);
            for (size_t z = 0; zero32 && z < 32; z++) {
                if (page_buf[z] != 0) zero32 = false;
            }
            bool zero16_31 = ((size_t)got >= 32 &&
                              !(page_buf[0] == 0x7f && page_buf[1] == 'E' && page_buf[2] == 'L' && page_buf[3] == 'F'));
            for (size_t z = 16; zero16_31 && z < 32; z++) {
                if (page_buf[z] != 0) zero16_31 = false;
            }
            if ((zero32 && vlen >= 0x10000 && !c->was_prev_rw) ||
                (zero16_31 && vlen >= (4ULL << 20) && (c->start & 0x3ffffULL) == 0 && !c->was_prev_rw)) {
                c->is_alloc_pool = true;
            }

            /* Check embedded reflective ELF header or raw `syscall` (`0f 05` not preceded by mov-imm) at entry */
            if (!c->is_alloc_pool && (size_t)got >= 4 &&
                page_buf[0] == 0x7f && page_buf[1] == 'E' && page_buf[2] == 'L' && page_buf[3] == 'F') {
                c->has_entry_syscall_stub = true;
            } else if (!c->is_alloc_pool && !zero32 && page_buf[0] != 0x00) {
                size_t scan_n = (size_t)got < 256 ? (size_t)got : 256;
                for (size_t k = 0; k + 1 < scan_n; k++) {
                    if (page_buf[k] == 0x0f && page_buf[k + 1] == 0x05) {
                        uint8_t prev = (k > 0) ? page_buf[k - 1] : 0;
                        if (!(prev >= 0xb8 && prev <= 0xbf) && prev != 0xc7) {
                            c->has_entry_syscall_stub = true;
                            break;
                        }
                    }
                }
            }
        }

        int vscore = 0;
        if (c->is_memfd) {
            vscore = 90;
        } else if (c->is_stack_or_heap) {
            vscore = 65;
        } else if (c->is_rwx) {
            if (c->is_alloc_pool) {
                vscore = 20;
            } else {
                vscore = 45 + (c->was_prev_rw ? 15 : 0) + (c->has_entry_syscall_stub ? 35 : 0);
            }
        } else if (c->is_w_to_x) {
            /* W^X-compliant `r-xp` anonymous region: benign JIT unless executing raw syscalls */
            vscore = 10 + (c->has_entry_syscall_stub ? 45 : 0);
        }

        if (vscore > best_vma_score) {
            best_vma_score = vscore;
            best_idx = i;
        }
    }

    if (best_idx < 0) {
        if (mem_fd >= 0) close(mem_fd);
        return false; /* All candidate VMAs were provably benign FFI trampolines */
    }

    /* Origin risk modifiers: additive score inputs ONLY (never exemptions, never sole triggers) */
    int origin_score = 0;
    if (is_untrusted_origin_path(pm->exe) || strstr(pm->exe, "(deleted)") != NULL) {
        origin_score = 20;
    } else if (is_untrusted_origin_path(pm->script_arg)) {
        origin_score = 10;
    }

    /* Fast non-intrusive execution-locus pass (`/proc/tid/syscall` + stack call-frames) */
    int exec_idx = -1, exec_score = 0;
    char exec_proof[64] = "none";
    uint64_t exec_rip = 0;
    inspect_threads_against_vmas(pm->pid, mem_fd, cands, cand_cnt, false,
                                 &exec_idx, exec_proof, sizeof(exec_proof), &exec_rip, &exec_score);

    int total_score = best_vma_score + origin_score + exec_score;

    /*
     * Graded Freeze & Deep Register Verification:
     * When anomalous raw W+X / W->X evidence reaches >= 45 (or raw RWX page exists
     * while threads are actively running on CPU), freeze task (`SIGSTOP` in enforce
     * mode, or non-destructive PTRACE_SEIZE sample in shadow mode) and verify exact RIP/RSP!
     */
    uint64_t freeze_us = 0;
    if (total_score >= 45) {
        if (!g_shadow_mode) {
            (void)amber_freeze_task(pm);
            freeze_us = (mono_ns() - t_detect_ns) / 1000ULL;
            if (freeze_us == 0) freeze_us = 1;
            /* Allow up to 200 us for remote-core IPI stop so `/proc/tid/syscall` exposes `-1 rsp rip` */
            for (int spin = 0; spin < 20 && exec_score == 0; spin++) {
                inspect_threads_against_vmas(pm->pid, mem_fd, cands, cand_cnt, false,
                                             &exec_idx, exec_proof, sizeof(exec_proof), &exec_rip, &exec_score);
                if (exec_score > 0) break;
                sched_yield();
            }
        } else {
            if (exec_score == 0) {
                inspect_threads_against_vmas(pm->pid, mem_fd, cands, cand_cnt, true,
                                             &exec_idx, exec_proof, sizeof(exec_proof), &exec_rip, &exec_score);
            }
            freeze_us = (mono_ns() - t_detect_ns) / 1000ULL;
            if (freeze_us == 0) freeze_us = 1;
        }
        total_score = best_vma_score + origin_score + exec_score;
    }

    if (mem_fd >= 0) close(mem_fd);

    if (total_score < 50) {
        if (!g_shadow_mode && freeze_us > 0) {
            (void)kill(pm->pid, SIGCONT);
        }
        return false;
    }

    const CandVma *v = &cands[(exec_idx >= 0) ? exec_idx : best_idx];
    out->vma_start = v->start;
    out->vma_end   = v->end;
    snprintf(out->vma_perms, sizeof(out->vma_perms), "%s", v->perms);
    snprintf(out->vma_backing, sizeof(out->vma_backing), "%s", v->backing);
    snprintf(out->vma_transition, sizeof(out->vma_transition), "%s",
             v->is_memfd ? "memfd_exec_map" :
             (v->is_rwx && v->was_prev_rw) ? "mprotect_rw_to_rwx" :
             v->is_rwx ? "mmap_or_mprotect_rwx" : "mprotect_rw_to_rx");
    snprintf(out->exec_proof, sizeof(out->exec_proof), "%s", exec_proof[0] ? exec_proof : "unconfirmed_at_sample");
    out->exec_rip   = exec_rip;
    out->risk_score = total_score;
    out->freeze_us  = freeze_us ? freeze_us : 1;

    if (total_score >= 80) {
        out->confidence = CONF_HIGH;
        out->decision   = DECISION_SIGKILL;
        snprintf(out->reason, sizeof(out->reason), "%s",
                 v->is_memfd ? "fileless_memfd_exec" : "anonymous_rwx_shellcode_injection");
    } else {
        out->confidence = CONF_MEDIUM;
        out->decision   = DECISION_FREEZE_CONTAIN;
        snprintf(out->reason, sizeof(out->reason), "suspicious_unverified_rwx_region");
    }

    snprintf(out->summary, sizeof(out->summary),
             "vma=0x%" PRIx64 "-0x%" PRIx64 "(%s,%s,trans=%s) exec=%s rip=0x%" PRIx64 " score=%d",
             out->vma_start, out->vma_end, out->vma_perms, out->vma_backing,
             out->vma_transition, out->exec_proof, out->exec_rip, out->risk_score);
    return true;
}

/* =========================================================================
 * Phase 3: Autonomous AI Surgeon (`Doctor`) — Forensic Triage & Remediation
 * ========================================================================= */
static bool recently_handled_pid(pid_t pid) {
    uint64_t now = mono_ns();
    for (int i = 0; i < MAX_HANDLED_PIDS; i++) {
        if (g_handled_pids[i] == pid && (now - g_handled_ns[i]) < 3000000000ULL) {
            return true;
        }
    }
    g_handled_pids[g_handled_idx] = pid;
    g_handled_ns[g_handled_idx] = now;
    g_handled_idx = (g_handled_idx + 1) % MAX_HANDLED_PIDS;
    return false;
}

static void handle_inotify_events(int ifd);

static void clean_persistence_artifacts(const ProcMeta *pm, char *cleaned_summary, size_t cap) {
    cleaned_summary[0] = '\0';
    size_t used = 0;
    if (g_ino_fd_global >= 0) {
        handle_inotify_events(g_ino_fd_global);
    }

    /* 1. Check /etc/ld.so.preload for untrusted .so entries */
    struct stat st;
    if (stat("/etc/ld.so.preload", &st) == 0 && st.st_size > 0) {
        char buf[1024];
        if (read_file_fast("/etc/ld.so.preload", buf, sizeof(buf)) > 0) {
            if (strstr(buf, "/tmp/") || strstr(buf, "/dev/shm/") || strstr(buf, "hshield_sim")) {
                unlink("/etc/ld.so.preload");
                used += (size_t)snprintf(cleaned_summary + used, cap - used, "/etc/ld.so.preload ");
            }
        }
    }

    /* 2. Check ~/.config/systemd/user for newly dropped untrusted persistence units */
    const char *u_sysd = USER_HOME "/.config/systemd/user";
    DIR *d = opendir(u_sysd);
    if (d) {
        time_t now = time(NULL);
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.') continue;
            if (!strstr(de->d_name, ".service") && !strstr(de->d_name, ".timer")) continue;
            /* Never touch hephaestus-* or zeromemory* units! */
            if (strncmp(de->d_name, "hephaestus-", 11) == 0 ||
                strncmp(de->d_name, "zeromemory", 10) == 0 ||
                strncmp(de->d_name, "zero-lifelog", 12) == 0) {
                continue;
            }
            char upath[512];
            snprintf(upath, sizeof(upath), "%s/%.200s", u_sysd, de->d_name);
            struct stat ust;
            if (stat(upath, &ust) == 0 && (now - ust.st_mtime) <= 15) {
                char ubuf[2048];
                if (read_file_fast(upath, ubuf, sizeof(ubuf)) > 0 &&
                    (strstr(ubuf, "/dev/shm/") || strstr(ubuf, "/tmp/") ||
                     strstr(ubuf, "/memfd:") || strstr(ubuf, "HSHIELD_SIM_PERSIST") ||
                     (pm->cwd[0] && strstr(ubuf, pm->cwd) && is_untrusted_origin_path(pm->cwd)))) {
                    unlink(upath);
                    if (used + 128 < cap) {
                        used += (size_t)snprintf(cleaned_summary + used, cap - used, "%s ", upath);
                    }
                }
            }
        }
        closedir(d);
    }

    /* 3. Drain pending inotify events FIRST so sub-ms file corruptions right before freeze are recorded! */
    uint64_t now_ns = mono_ns();
    for (int i = 0; i < MAX_RECENT_MODS; i++) {
        RecentModEntry *rm = &g_recent_mods[i];
        if (!rm->path[0] || (now_ns - rm->mod_ns) > 8000000000ULL) continue;
        if (rm->is_integrity_target) {
            uint64_t r_us = 0;
            if (restore_file_cow_fast(rm->path, &r_us)) {
                if (used + 160 < cap) {
                    used += (size_t)snprintf(cleaned_summary + used, cap - used,
                                             "cow_restored:%s(%" PRIu64 "us) ", rm->path, r_us);
                }
            }
            rm->path[0] = '\0';
        }
    }
}

static void surgeon_record_and_respond(const ProcMeta *pm, const char *trigger,
                                       const char *extra_detail, uint64_t freeze_us,
                                       ConfidenceTier conf, ResponseDecision decision,
                                       const WxAssessment *wx_opt) {
    uint64_t t_start = mono_ns();
    mkdir_p(g_quarantine_dir, 0755, USER_UID, USER_GID);
    mkdir_p(g_forensics_dir, 0755, USER_UID, USER_GID);

    g_incidents_total++;
    g_last_freeze_us = freeze_us;

    char inc_id[64];
    snprintf(inc_id, sizeof(inc_id), "inc_%lld_%d_%u",
             (long long)time(NULL), (int)pm->pid, g_incidents_total);

    /* 1. Capture Forensic Snapshot (`/proc/<pid>/maps`, FDs, C2 sockets, parent chain) */
    char maps_sample[2048] = {0};
    char mpath[128];
    snprintf(mpath, sizeof(mpath), "/proc/%d/maps", (int)pm->pid);
    (void)read_file_fast(mpath, maps_sample, sizeof(maps_sample));

    char fds_summary[1024] = {0};
    char c2_ips[256] = {0};
    size_t fd_used = 0, c2_used = 0;
    char fdpath[128];
    snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd", (int)pm->pid);
    DIR *fdd = opendir(fdpath);
    if (fdd) {
        struct dirent *de;
        int cnt = 0;
        while ((de = readdir(fdd)) != NULL && cnt < 16) {
            if (!isdigit((unsigned char)de->d_name[0])) continue;
            char lp[256], target[256] = {0};
            snprintf(lp, sizeof(lp), "/proc/%d/fd/%.32s", (int)pm->pid, de->d_name);
            if (readlink(lp, target, sizeof(target) - 1) > 0) {
                if (fd_used + 96 < sizeof(fds_summary)) {
                    fd_used += (size_t)snprintf(fds_summary + fd_used, sizeof(fds_summary) - fd_used,
                                                "fd%s->%.64s; ", de->d_name, target);
                }
                unsigned long ino = 0;
                if (sscanf(target, "socket:[%lu]", &ino) == 1) {
                    char rip[64] = {0};
                    uint16_t rp = 0;
                    if (lookup_tcp_remote_by_inode(ino, rip, sizeof(rip), &rp)) {
                        if (!g_shadow_mode && conf == CONF_HIGH) nft_block_ipv4(rip);
                        if (c2_used + 48 < sizeof(c2_ips)) {
                            c2_used += (size_t)snprintf(c2_ips + c2_used, sizeof(c2_ips) - c2_used,
                                                        "%s:%u ", rip, rp);
                        }
                    }
                }
                cnt++;
            }
        }
        closedir(fdd);
    }

    /* Parent chain (3 levels) */
    char parent_chain[512] = {0};
    size_t pc_used = 0;
    pid_t cur_ppid = pm->ppid;
    for (int lvl = 0; lvl < 3 && cur_ppid > 1; lvl++) {
        ProcMeta ppm;
        if (!read_proc_meta(cur_ppid, &ppm)) break;
        if (pc_used + 120 < sizeof(parent_chain)) {
            pc_used += (size_t)snprintf(parent_chain + pc_used, sizeof(parent_chain) - pc_used,
                                        "%d(%.40s)%s", (int)ppm.pid, ppm.comm, (lvl < 2) ? " <- " : "");
        }
        cur_ppid = ppm.ppid;
    }

    char code_slice[1024] = {0};
    if (pm->script_arg[0] != '\0') {
        (void)read_file_fast(pm->script_arg, code_slice, sizeof(code_slice));
    }

    /* 2. Quarantine Payload & Execute Graded Response (Enforce vs Shadow) */
    char q_source[512] = {0};
    bool unlink_standalone_dropper = false;
    bool is_memfd_exe = (strncmp(pm->exe, "/memfd:", 7) == 0 || strstr(pm->exe, "/memfd:") != NULL);
    if (pm->script_arg[0] != '\0' && is_untrusted_origin_path(pm->script_arg)) {
        snprintf(q_source, sizeof(q_source), "%.500s", pm->script_arg);
        /* Never auto-delete user scripts on disk; encrypt copy + hash SHA-256 only on HIGH confidence */
        unlink_standalone_dropper = false;
    } else if (is_memfd_exe) {
        snprintf(q_source, sizeof(q_source), "/proc/%d/exe", (int)pm->pid);
        unlink_standalone_dropper = false;
    } else if (is_untrusted_origin_path(pm->exe)) {
        snprintf(q_source, sizeof(q_source), "%.500s", pm->exe);
        unlink_standalone_dropper = (conf == CONF_HIGH);
    } else {
        snprintf(q_source, sizeof(q_source), "/proc/%d/exe", (int)pm->pid);
    }

    char qenc_path[640] = "", qmeta_path[640] = "";
    uint8_t sha256[32] = {0};
    bool has_sha = false;
    char sha_hex[65] = "none";

    if (!g_shadow_mode && conf == CONF_HIGH) {
        snprintf(qenc_path, sizeof(qenc_path), "%s/%s.qenc", g_quarantine_dir, inc_id);
        snprintf(qmeta_path, sizeof(qmeta_path), "%s/%s.json", g_quarantine_dir, inc_id);
        has_sha = quarantine_encrypt_file(q_source, qenc_path, sha256);
        if (has_sha) bytes_to_hex(sha256, 32, sha_hex);

        if (unlink_standalone_dropper && q_source[0] == '/' && strncmp(q_source, "/proc/", 6) != 0) {
            (void)chmod(q_source, 0000);
            (void)unlink(q_source);
        }
    } else if (sha256_file(q_source, sha256)) {
        has_sha = true;
        bytes_to_hex(sha256, 32, sha_hex);
    }

    /* 3. Graded Task-Scoped Action: SIGKILL (HIGH) vs SIGSTOP Freeze Containment (MEDIUM) */
    if (!g_shadow_mode) {
        if (decision == DECISION_SIGKILL) {
            eradicate_task(pm);
        } else if (decision == DECISION_FREEZE_CONTAIN) {
            (void)amber_freeze_task(pm);
        }
    }

    /* 4. Clean Persistence Hooks & Restore Integrity Targets ONLY on Enforce HIGH */
    char cleaned_buf[1024] = {0};
    if (!g_shadow_mode && conf == CONF_HIGH) {
        clean_persistence_artifacts(pm, cleaned_buf, sizeof(cleaned_buf));
    }

    /*
     * 5. Evolve Immune Memory (`shield_rules.bin`):
     * Synthesize SHA-256 content antibodies ONLY on HIGH-confidence untrusted payloads.
     * NEVER auto-synthesize mutable file-path substring patterns (`rule_pat`), which
     * previously caused 30 secondary FPs on `timeout`, `rm`, `cp`, `cat`, `pgrep`, and edited scripts!
     */
    if (!g_shadow_mode && conf == CONF_HIGH && has_sha &&
        (is_memfd_exe || is_untrusted_origin_path(pm->exe) ||
         (pm->script_arg[0] && is_untrusted_origin_path(pm->script_arg)))) {
        (void)add_immune_rule(sha256, NULL, trigger);
    }

    uint64_t total_us = (mono_ns() - t_start) / 1000ULL;

    const char *conf_str = (conf == CONF_HIGH) ? "high" : (conf == CONF_MEDIUM) ? "medium" : "low";
    const char *dec_str  = g_shadow_mode
        ? ((decision == DECISION_SIGKILL) ? "shadow_would_sigkill" : "shadow_would_freeze_contain")
        : ((decision == DECISION_SIGKILL) ? "sigkill_task" : "freeze_contain_task");

    char exe_e[640], cmd_e[1200], par_e[640], fds_e[1200], maps_e[2400], code_e[1200], cln_e[1200], det_e[512], wx_e[640];
    json_escape(pm->exe, exe_e, sizeof(exe_e));
    json_escape(pm->cmdline, cmd_e, sizeof(cmd_e));
    json_escape(parent_chain, par_e, sizeof(par_e));
    json_escape(fds_summary, fds_e, sizeof(fds_e));
    json_escape(maps_sample, maps_e, sizeof(maps_e));
    json_escape(code_slice, code_e, sizeof(code_e));
    json_escape(cleaned_buf, cln_e, sizeof(cln_e));
    json_escape(extra_detail ? extra_detail : "", det_e, sizeof(det_e));
    json_escape(wx_opt ? wx_opt->summary : "", wx_e, sizeof(wx_e));

    char fpath[640];
    snprintf(fpath, sizeof(fpath), "%s/%s.json", g_forensics_dir, inc_id);
    char report[8192];
    int rlen = snprintf(
        report, sizeof(report),
        "{\n"
        "  \"incident_id\": \"%s\",\n"
        "  \"ts\": %" PRIu64 ",\n"
        "  \"shadow\": %s,\n"
        "  \"confidence\": \"%s\",\n"
        "  \"risk_score\": %d,\n"
        "  \"decision\": \"%s\",\n"
        "  \"trigger\": \"%s\",\n"
        "  \"detail\": \"%s\",\n"
        "  \"vma_evidence\": \"%s\",\n"
        "  \"pid\": %d,\n"
        "  \"ppid\": %d,\n"
        "  \"pgid\": %d,\n"
        "  \"exe\": \"%s\",\n"
        "  \"cmdline\": \"%s\",\n"
        "  \"parent_chain\": \"%s\",\n"
        "  \"sha256\": \"%s\",\n"
        "  \"quarantine_file\": \"%s\",\n"
        "  \"freeze_latency_us\": %" PRIu64 ",\n"
        "  \"total_surgeon_us\": %" PRIu64 ",\n"
        "  \"c2_blocked\": \"%s\",\n"
        "  \"remediation\": \"%s\",\n"
        "  \"open_fds\": \"%s\",\n"
        "  \"code_slice\": \"%s\",\n"
        "  \"maps_head\": \"%s\"\n"
        "}\n",
        inc_id, (uint64_t)time(NULL),
        g_shadow_mode ? "true" : "false",
        conf_str,
        wx_opt ? wx_opt->risk_score : ((conf == CONF_HIGH) ? 100 : 60),
        dec_str,
        trigger, det_e, wx_e,
        (int)pm->pid, (int)pm->ppid, (int)pm->pgid,
        exe_e, cmd_e, par_e, sha_hex, qenc_path,
        freeze_us, total_us, c2_ips, cln_e, fds_e, code_e, maps_e
    );
    if (rlen > 0) {
        (void)write_file_atomic(fpath, report, (size_t)rlen, 0644);
        if (chown(fpath, USER_UID, USER_GID) != 0) { /* ignore */ }
        if (qmeta_path[0]) {
            (void)write_file_atomic(qmeta_path, report, (size_t)rlen, 0644);
            if (chown(qmeta_path, USER_UID, USER_GID) != 0) { /* ignore */ }
        }
    }

    snprintf(g_last_incident, sizeof(g_last_incident), "%s:%s(%s,pid=%d,freeze=%" PRIu64 "us)",
             inc_id, trigger, dec_str, (int)pm->pid, freeze_us);
    refresh_status_shm(true);

    if (!g_shadow_mode && conf == CONF_HIGH) {
        char zm_title[160], zm_body[512];
        snprintf(zm_title, sizeof(zm_title), "hshield Antibody: %.80s", trigger);
        snprintf(zm_body, sizeof(zm_body),
                 "Threat %.80s neutralized in %" PRIu64 "us freeze / %" PRIu64 "us surgeon. "
                 "exe=%.100s sha256=%.64s remediation=%.100s",
                 trigger, freeze_us, total_us, pm->exe, sha_hex, cleaned_buf[0] ? cleaned_buf : "quarantined");
        ingest_antibody_zeromemory_async(zm_title, zm_body);
    }
}

/* =========================================================================
 * Fast <0.08ms Compiled Antibody Matcher on `PROC_EVENT_EXEC`
 * ========================================================================= */
static bool match_compiled_antibody(const ProcMeta *pm, char *reason_out, size_t rcap) {
    if (!g_rules_shm || g_rules_shm->magic != HSHIELD_RULE_MAGIC || g_rules_shm->count == 0) {
        return false;
    }
    uint32_t cnt = g_rules_shm->count;
    if (cnt > HSHIELD_MAX_RULES) cnt = HSHIELD_MAX_RULES;

    /*
     * Pass 1: Explicit pattern check strictly against `pm->exe` or verified interpreter
     * `pm->script_arg` (NEVER arbitrary `cmdline` substrings on `rm`, `cp`, `timeout`, `pgrep`!).
     */
    for (uint32_t i = 0; i < cnt; i++) {
        ShieldRuleBin *r = &g_rules_shm->rules[i];
        if (r->has_pattern && r->pattern[0]) {
            bool hit = false;
            if (r->pattern[0] == '/') {
                hit = (pm->exe[0] && strcmp(pm->exe, r->pattern) == 0) ||
                      (pm->script_arg[0] && strcmp(pm->script_arg, r->pattern) == 0);
            } else {
                hit = (pm->exe[0] && strstr(pm->exe, r->pattern) != NULL) ||
                      (pm->script_arg[0] && strstr(pm->script_arg, r->pattern) != NULL);
            }
            if (hit) {
                if (!g_shadow_mode) {
                    r->hit_count++;
                    g_rules_shm->total_blocks++;
                    g_immune_fast_blocks++;
                }
                snprintf(reason_out, rcap, "immune_antibody_pattern:%.64s", r->reason);
                return true;
            }
        }
    }

    /* Pass 2: SHA-256 content match on untrusted binary or interpreter script (~25 us) */
    const char *hash_target = NULL;
    if (pm->script_arg[0] && is_untrusted_origin_path(pm->script_arg)) {
        hash_target = pm->script_arg;
    } else if (is_untrusted_origin_path(pm->exe)) {
        char pexe[128];
        snprintf(pexe, sizeof(pexe), "/proc/%d/exe", (int)pm->pid);
        uint8_t digest[32];
        if (sha256_file(pexe, digest)) {
            for (uint32_t i = 0; i < cnt; i++) {
                ShieldRuleBin *r = &g_rules_shm->rules[i];
                if (r->has_sha256 && memcmp(r->sha256, digest, 32) == 0) {
                    if (!g_shadow_mode) {
                        r->hit_count++;
                        g_rules_shm->total_blocks++;
                        g_immune_fast_blocks++;
                    }
                    snprintf(reason_out, rcap, "immune_antibody_sha256:%.64s", r->reason);
                    return true;
                }
            }
        }
        return false;
    }
    if (hash_target) {
        uint8_t digest[32];
        if (sha256_file(hash_target, digest)) {
            for (uint32_t i = 0; i < cnt; i++) {
                ShieldRuleBin *r = &g_rules_shm->rules[i];
                if (r->has_sha256 && memcmp(r->sha256, digest, 32) == 0) {
                    if (!g_shadow_mode) {
                        r->hit_count++;
                        g_rules_shm->total_blocks++;
                        g_immune_fast_blocks++;
                    }
                    snprintf(reason_out, rcap, "immune_antibody_sha256:%.64s", r->reason);
                    return true;
                }
            }
        }
    }
    return false;
}

/* =========================================================================
 * Canary Traps (`fanotify`), Persistence (`inotify`), & `CN_PROC` Setup
 * ========================================================================= */
static const char *CANARY_PATHS[] = {
    USER_HOME "/.ssh/.id_ed25519_prod_canary",
    VAULT_DIR "/.canary_master.key",
    USER_HOME "/.gnupg/.secring_canary.gpg"
};

static void provision_canaries(void) {
    mkdir_p(USER_HOME "/.ssh", 0700, USER_UID, USER_GID);
    mkdir_p(VAULT_DIR, 0700, USER_UID, USER_GID);
    mkdir_p(USER_HOME "/.gnupg", 0700, USER_UID, USER_GID);

    const char *payloads[3] = {
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
        "HSHIELD_CANARY_TRAP_DO_NOT_TOUCH_9f8e7d6c5b4a3210\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
        "HSHIELD_VAULT_CANARY_MASTER_KEY_v5=7f9a2c4b8e1d0f3a6c5b9e8d7f2a1c4b\n",
        "HSHIELD_GNUPG_CANARY_SECRING_v5_DO_NOT_OPEN\n"
    };

    for (size_t i = 0; i < 3; i++) {
        struct stat st;
        if (stat(CANARY_PATHS[i], &st) != 0) {
            (void)write_file_atomic(CANARY_PATHS[i], payloads[i], strlen(payloads[i]), 0600);
            if (chown(CANARY_PATHS[i], USER_UID, USER_GID) != 0) { /* ignore */ }
        }
    }
}

static int setup_fanotify_canaries(void) {
    provision_canaries();
    int ffd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (ffd < 0) return -1;

    for (size_t i = 0; i < 3; i++) {
        (void)fanotify_mark(ffd, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, CANARY_PATHS[i]);
    }
    struct stat vst;
    if (stat(VAULT_ENC_PATH, &vst) == 0) {
        (void)fanotify_mark(ffd, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, VAULT_ENC_PATH);
    }
    return ffd;
}

static bool is_authorized_vault_reader(const ProcMeta *pm) {
    if (pm->pid == getpid()) return true;
    if (strcmp(pm->exe, "/usr/bin/btrfs") == 0 || strcmp(pm->exe, "/usr/bin/snapper") == 0) return true;
    /* hvault is a Python tool in /usr/local/bin/hvault or ~/.local/bin/hvault */
    if (strstr(pm->cmdline, "/usr/local/bin/hvault") ||
        strstr(pm->cmdline, "/usr/local/bin/hvault") ||
        strstr(pm->cmdline, "projects/hephaestus-core/bin/hvault")) {
        /* Reject if piped or invoked from /dev/shm or /tmp wrapper */
        if (!strstr(pm->cmdline, "/dev/shm/") && !strstr(pm->cmdline, "/tmp/")) {
            return true;
        }
    }
    return false;
}

static void handle_fanotify_events(int ffd) {
    struct fanotify_event_metadata buf[64];
    ssize_t len = read(ffd, buf, sizeof(buf));
    if (len <= 0) return;

    const struct fanotify_event_metadata *md = buf;
    while (FAN_EVENT_OK(md, len)) {
        if (md->vers == FANOTIFY_METADATA_VERSION && md->fd >= 0) {
            if (md->mask & FAN_OPEN_PERM) {
                char fdlink[64], target_path[512] = {0};
                snprintf(fdlink, sizeof(fdlink), "/proc/self/fd/%d", md->fd);
                ssize_t rl = readlink(fdlink, target_path, sizeof(target_path) - 1);
                if (rl > 0) target_path[rl] = '\0';

                ProcMeta pm;
                bool have_pm = read_proc_meta((pid_t)md->pid, &pm);
                bool is_vault = (strcmp(target_path, VAULT_ENC_PATH) == 0);
                bool allow = false;

                if (md->pid == getpid()) {
                    allow = true;
                } else if (is_vault && have_pm && is_authorized_vault_reader(&pm)) {
                    allow = true;
                } else if (!is_vault && have_pm &&
                           (strcmp(pm.exe, "/usr/bin/btrfs") == 0 || strcmp(pm.exe, "/usr/bin/snapper") == 0)) {
                    allow = true;
                }

                struct fanotify_response resp;
                resp.fd = md->fd;
                resp.response = allow ? FAN_ALLOW : FAN_DENY;

                if (!allow) {
                    if (!g_shadow_mode) g_canary_blocks++;
                    if (have_pm && !is_sacred_core(&pm) &&
                        strcmp(pm.comm, "rg") != 0 && strcmp(pm.comm, "git") != 0) {
                        /* Queue task-scoped SIGSTOP BEFORE releasing FAN_DENY so attacker freezes with 0 bytes read! */
                        uint64_t freeze_us = amber_freeze_task(&pm);
                        if (write(ffd, &resp, sizeof(resp)) < 0) {}
                        close(md->fd);
                        if (!recently_handled_pid(pm.pid)) {
                            surgeon_record_and_respond(
                                &pm,
                                is_vault ? "unauthorized_vault_access" : "canary_trap_tripped",
                                target_path,
                                freeze_us,
                                CONF_HIGH,
                                DECISION_SIGKILL,
                                NULL
                            );
                        }
                        md = FAN_EVENT_NEXT(md, len);
                        continue;
                    } else {
                        snprintf(g_last_incident, sizeof(g_last_incident),
                                 "canary_denied_safe(pid=%d,comm=%.32s,file=%.80s)",
                                 (int)md->pid, have_pm ? pm.comm : "?", target_path);
                        refresh_status_shm(true);
                    }
                }
                if (write(ffd, &resp, sizeof(resp)) < 0) {}
            }
            close(md->fd);
        }
        md = FAN_EVENT_NEXT(md, len);
    }
}

static void add_inotify_watch_path(int ifd, const char *path, bool is_integrity_target) {
    if (ifd < 0 || !path || !path[0]) return;
    /* Update existing watch if already registered */
    for (int i = 0; i < g_watch_count; i++) {
        if (strcmp(g_watches[i].path, path) == 0) {
            g_watches[i].is_integrity_target = is_integrity_target;
            return;
        }
    }
    if (g_watch_count >= MAX_INOTIFY_WATCHES) return;
    uint32_t mask = IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE | IN_MOVED_TO | IN_ATTRIB;
    int wd = inotify_add_watch(ifd, path, mask);
    if (wd >= 0) {
        g_watches[g_watch_count].wd = wd;
        g_watches[g_watch_count].is_integrity_target = is_integrity_target;
        snprintf(g_watches[g_watch_count].path, sizeof(g_watches[g_watch_count].path), "%.500s", path);
        g_watch_count++;
    }
}

static int setup_inotify_persistence(void) {
    int ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ifd < 0) return -1;
    mkdir_p(USER_HOME "/.config/systemd/user", 0755, USER_UID, USER_GID);
    add_inotify_watch_path(ifd, "/etc/systemd/system", false);
    add_inotify_watch_path(ifd, USER_HOME "/.config/systemd/user", false);
    add_inotify_watch_path(ifd, USER_HOME "/.ssh", false);
    add_inotify_watch_path(ifd, USER_HOME "/.bashrc", false);
    add_inotify_watch_path(ifd, USER_HOME "/.profile", false);
    return ifd;
}

static void handle_inotify_events(int ifd) {
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    ssize_t len = read(ifd, buf, sizeof(buf));
    if (len <= 0) return;
    ssize_t off = 0;
    while (off < len) {
        const struct inotify_event *ev = (const struct inotify_event *)(buf + off);
        for (int i = 0; i < g_watch_count; i++) {
            if (g_watches[i].wd == ev->wd) {
                RecentModEntry *rm = &g_recent_mods[g_recent_mod_idx];
                g_recent_mod_idx = (g_recent_mod_idx + 1) % MAX_RECENT_MODS;
                rm->mod_ns = mono_ns();
                rm->is_integrity_target = g_watches[i].is_integrity_target;
                rm->was_created = (ev->mask & (IN_CREATE | IN_MOVED_TO)) != 0;
                if (ev->len > 0 && ev->name[0]) {
                    snprintf(rm->path, sizeof(rm->path), "%.250s/%.250s", g_watches[i].path, ev->name);
                } else {
                    snprintf(rm->path, sizeof(rm->path), "%.500s", g_watches[i].path);
                }
                break;
            }
        }
        off += (ssize_t)sizeof(struct inotify_event) + (ssize_t)ev->len;
    }
}

static int setup_cn_proc_netlink(void) {
    int nl_fd = socket(PF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_CONNECTOR);
    if (nl_fd < 0) return -1;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = CN_IDX_PROC;
    sa.nl_pid = (uint32_t)getpid();

    if (bind(nl_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(nl_fd);
        return -1;
    }

    struct __attribute__((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__((__packed__)) {
            struct cn_msg cn_hdr;
            enum proc_cn_mcast_op cn_mcast;
        };
    } msg;

    memset(&msg, 0, sizeof(msg));
    msg.nl_hdr.nlmsg_len = sizeof(msg);
    msg.nl_hdr.nlmsg_pid = (uint32_t)getpid();
    msg.nl_hdr.nlmsg_type = NLMSG_DONE;
    msg.cn_hdr.id.idx = CN_IDX_PROC;
    msg.cn_hdr.id.val = CN_VAL_PROC;
    msg.cn_hdr.len = sizeof(enum proc_cn_mcast_op);
    msg.cn_mcast = PROC_CN_MCAST_LISTEN;

    if (send(nl_fd, &msg, sizeof(msg), 0) < 0) {
        close(nl_fd);
        return -1;
    }
    return nl_fd;
}

static void arm_inspect_timer(int tfd) {
    uint64_t earliest = UINT64_MAX;
    for (int i = 0; i < MAX_PENDING_INSPECT; i++) {
        if (g_pending[i].pid > 0 && g_pending[i].due_ns < earliest) {
            earliest = g_pending[i].due_ns;
        }
    }
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    if (earliest != UINT64_MAX) {
        uint64_t now = mono_ns();
        uint64_t diff = (earliest > now) ? (earliest - now) : 1000000ULL;
        its.it_value.tv_sec = (time_t)(diff / 1000000000ULL);
        its.it_value.tv_nsec = (long)(diff % 1000000000ULL);
    }
    (void)timerfd_settime(tfd, 0, &its, NULL);
}

static void enqueue_micro_inspect(int tfd, const ProcMeta *pm) {
    uint64_t due = mono_ns() + 8000000ULL; /* Stage 0 at +8 ms (captures baseline RW VMAs & fast C stagers) */
    int free_idx = -1;
    for (int i = 0; i < MAX_PENDING_INSPECT; i++) {
        if (g_pending[i].pid == pm->pid) {
            free_idx = i;
            break;
        }
        if (free_idx < 0 && g_pending[i].pid == 0) {
            free_idx = i;
        }
    }
    if (free_idx >= 0) {
        memset(&g_pending[free_idx], 0, sizeof(g_pending[free_idx]));
        g_pending[free_idx].pid = pm->pid;
        g_pending[free_idx].due_ns = due;
        g_pending[free_idx].stage = 0;
        g_pending[free_idx].pm = *pm;
        arm_inspect_timer(tfd);
    }
}

static void handle_micro_inspect_timer(int tfd) {
    uint64_t exp = 0;
    if (read(tfd, &exp, sizeof(exp)) < 0) {}
    uint64_t now = mono_ns();
    for (int i = 0; i < MAX_PENDING_INSPECT; i++) {
        if (g_pending[i].pid <= 0 || g_pending[i].due_ns > now) continue;
        pid_t pid = g_pending[i].pid;
        if (kill(pid, 0) != 0 && errno == ESRCH) {
            g_pending[i].pid = 0;
            continue;
        }
        uint64_t t_det = mono_ns();
        WxAssessment wx;
        if (assess_wx_injection(&g_pending[i].pm, &g_pending[i], t_det, &wx)) {
            ProcMeta pm_snap = g_pending[i].pm;
            g_pending[i].pid = 0;
            if (!recently_handled_pid(pm_snap.pid)) {
                surgeon_record_and_respond(&pm_snap, wx.reason, "delayed_micro_inspect",
                                           wx.freeze_us, wx.confidence, wx.decision, &wx);
            }
        } else if (g_pending[i].stage == 0) {
            g_pending[i].stage = 1;
            g_pending[i].due_ns = now + 37000000ULL; /* Stage 1 at +45 ms */
        } else if (g_pending[i].stage == 1) {
            g_pending[i].stage = 2;
            g_pending[i].due_ns = now + 155000000ULL; /* Stage 2 at +200 ms, then 0 wakeups! */
        } else {
            g_pending[i].pid = 0;
        }
    }
    arm_inspect_timer(tfd);
}

static void handle_exec_pid(pid_t pid, int tfd) {
    if (pid <= 2 || pid == getpid()) return;

    /* Ultra-fast <50us compiled SHA-256 antibody pre-filter on untrusted binaries */
    if (g_rules_shm && g_rules_shm->magic == HSHIELD_RULE_MAGIC && g_rules_shm->count > 0) {
        char pexe[64], exelink[512];
        snprintf(pexe, sizeof(pexe), "/proc/%d/exe", (int)pid);
        ssize_t rl = readlink(pexe, exelink, sizeof(exelink) - 1);
        if (rl > 0) {
            exelink[rl] = '\0';
            if (is_untrusted_origin_path(exelink)) {
                uint64_t t_ab0 = mono_ns();
                uint8_t digest[32];
                if (sha256_file(pexe, digest)) {
                    uint32_t cnt = g_rules_shm->count > HSHIELD_MAX_RULES ? HSHIELD_MAX_RULES : g_rules_shm->count;
                    for (uint32_t i = 0; i < cnt; i++) {
                        ShieldRuleBin *r = &g_rules_shm->rules[i];
                        if (r->has_sha256 && memcmp(r->sha256, digest, 32) == 0) {
                            if (!g_shadow_mode) (void)kill(pid, SIGSTOP);
                            uint64_t fast_us = (mono_ns() - t_ab0) / 1000ULL;
                            if (fast_us == 0) fast_us = 1;
                            if (!g_shadow_mode) {
                                r->hit_count++;
                                g_rules_shm->total_blocks++;
                                g_immune_fast_blocks++;
                            }
                            ProcMeta pm;
                            if (read_proc_meta(pid, &pm) && !is_sacred_core(&pm)) {
                                (void)amber_freeze_task(&pm);
                                if (!recently_handled_pid(pm.pid)) {
                                    char rsn[160];
                                    snprintf(rsn, sizeof(rsn), "immune_antibody_sha256:%.64s", r->reason);
                                    surgeon_record_and_respond(&pm, rsn, "compiled_antibody_0token_block",
                                                               fast_us, CONF_HIGH, DECISION_SIGKILL, NULL);
                                }
                            }
                            return;
                        }
                    }
                }
            }
        }
    }

    uint64_t t_detect = mono_ns();
    ProcMeta pm;
    if (!read_proc_meta(pid, &pm)) return;

    /* Step 1: Sacred Core Fast-Allow */
    if (is_sacred_core(&pm)) return;

    /* Step 2: <0.08 ms Compiled Antibody Check for script interpreters / patterns (0 tokens!) */
    char reason[160] = {0};
    if (match_compiled_antibody(&pm, reason, sizeof(reason))) {
        (void)amber_freeze_task(&pm);
        uint64_t fast_us = (mono_ns() - t_detect) / 1000ULL;
        if (fast_us == 0) fast_us = 1;
        if (!recently_handled_pid(pm.pid)) {
            surgeon_record_and_respond(&pm, reason, "compiled_antibody_0token_block",
                                       fast_us, CONF_HIGH, DECISION_SIGKILL, NULL);
        }
        return;
    }

    /* Step 3: Immediate Exec Indicators (`memfd`, `LD_PRELOAD`, reverse shell, cryptominer) */
    if (check_suspicious_exec_indicators(&pm, reason, sizeof(reason))) {
        uint64_t freeze_us = amber_freeze_task(&pm);
        uint64_t total_freeze_us = (mono_ns() - t_detect) / 1000ULL;
        if (total_freeze_us < freeze_us) total_freeze_us = freeze_us;
        if (!recently_handled_pid(pm.pid)) {
            surgeon_record_and_respond(&pm, reason, "cn_proc_exec_radar",
                                       total_freeze_us, CONF_HIGH, DECISION_SIGKILL, NULL);
        }
        return;
    }

    /*
     * Step 4: Schedule 3-shot event-driven W+X / W->X micro-inspection across user
     * processes (not path-gated to /dev/shm alone: /dev/shm is strictly an additive
     * risk score input inside `assess_wx_injection`, never a gate or exemption!).
     */
    if (pm.uid == USER_UID || is_untrusted_origin_path(pm.exe) || is_untrusted_origin_path(pm.script_arg)) {
        enqueue_micro_inspect(tfd, &pm);
    }
}

static void handle_cn_proc_events(int nl_fd, int tfd) {
    uint8_t buf[8192] __attribute__((aligned(NLMSG_ALIGNTO)));
    for (;;) {
        ssize_t len = recv(nl_fd, buf, sizeof(buf), 0);
        if (len <= 0) break;
        for (struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
             NLMSG_OK(nlh, (uint32_t)len);
             nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type == NLMSG_NOOP) continue;
            struct cn_msg *cn = (struct cn_msg *)NLMSG_DATA(nlh);
            if (cn->id.idx != CN_IDX_PROC || cn->id.val != CN_VAL_PROC) continue;
            struct proc_event *ev = (struct proc_event *)cn->data;
            if (ev->what == PROC_EVENT_EXEC) {
                handle_exec_pid((pid_t)ev->event_data.exec.process_tgid, tfd);
            }
        }
    }
}

/* =========================================================================
 * UNIX Domain Control Socket (`/run/hephaestus-shield.sock`)
 * ========================================================================= */
static int setup_control_socket(void) {
    unlink(g_ctrl_sock_path);
    int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sfd < 0) return -1;
    struct sockaddr_un su;
    memset(&su, 0, sizeof(su));
    su.sun_family = AF_UNIX;
    snprintf(su.sun_path, sizeof(su.sun_path), "%s", g_ctrl_sock_path);
    if (bind(sfd, (struct sockaddr *)&su, sizeof(su)) < 0) {
        close(sfd);
        return -1;
    }
    (void)chmod(g_ctrl_sock_path, 0666);
    if (listen(sfd, 16) < 0) {
        close(sfd);
        return -1;
    }
    return sfd;
}

static void handle_control_client(int sfd, int ifd, int ffd) {
    int cfd = accept4(sfd, NULL, NULL, SOCK_CLOEXEC);
    if (cfd < 0) return;

    struct ucred cr;
    socklen_t clen = sizeof(cr);
    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cr, &clen) != 0 ||
        (cr.uid != 0 && cr.uid != USER_UID)) {
        close(cfd);
        return;
    }

    char cmd[1024];
    ssize_t n = read(cfd, cmd, sizeof(cmd) - 1);
    if (n <= 0) {
        close(cfd);
        return;
    }
    cmd[n] = '\0';
    while (n > 0 && (cmd[n - 1] == '\n' || cmd[n - 1] == '\r')) cmd[--n] = '\0';

    char reply[512] = "{\"ok\":false}\n";
    if (strncmp(cmd, "EVOLVE\t", 7) == 0) {
        /* Format: EVOLVE\t<sha256_or_->\t<pattern_or_->\t<reason> */
        char *p1 = cmd + 7;
        char *t1 = strchr(p1, '\t');
        if (t1) {
            *t1 = '\0';
            char *p2 = t1 + 1;
            char *t2 = strchr(p2, '\t');
            if (t2) {
                *t2 = '\0';
                char *p3 = t2 + 1;
                uint8_t sha[32];
                const uint8_t *sha_ptr = NULL;
                if (strlen(p1) == 64 && hex_to_bytes(p1, sha, 32)) sha_ptr = sha;
                const char *pat_ptr = (strcmp(p2, "-") != 0 && p2[0]) ? p2 : NULL;
                bool ok = add_immune_rule(sha_ptr, pat_ptr, p3);
                refresh_status_shm(true);
                snprintf(reply, sizeof(reply), "{\"ok\":%s,\"rules\":%u}\n",
                         ok ? "true" : "false", g_rules_shm ? g_rules_shm->count : 0U);
            }
        }
    } else if (strncmp(cmd, "WATCH\t", 6) == 0) {
        const char *wpath = cmd + 6;
        add_inotify_watch_path(ifd, wpath, true);
        snprintf(reply, sizeof(reply), "{\"ok\":true,\"watched\":\"%.200s\"}\n", wpath);
    } else if (strncmp(cmd, "RESTORE\t", 8) == 0) {
        const char *rpath = cmd + 8;
        uint64_t us = 0;
        bool ok = restore_file_cow_fast(rpath, &us);
        refresh_status_shm(true);
        snprintf(reply, sizeof(reply), "{\"ok\":%s,\"elapsed_us\":%" PRIu64 ",\"elapsed_ms\":%.3f}\n",
                 ok ? "true" : "false", us, (double)us / 1000.0);
    } else if (strcmp(cmd, "RELOAD_CANARIES") == 0) {
        provision_canaries();
        if (ffd >= 0) {
            for (size_t i = 0; i < 3; i++) {
                (void)fanotify_mark(ffd, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, CANARY_PATHS[i]);
            }
            struct stat vst;
            if (stat(VAULT_ENC_PATH, &vst) == 0) {
                (void)fanotify_mark(ffd, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, VAULT_ENC_PATH);
            }
        }
        refresh_status_shm(true);
        snprintf(reply, sizeof(reply), "{\"ok\":true}\n");
    } else if (strncmp(cmd, "SHADOW\t", 7) == 0) {
        g_shadow_mode = (cmd[7] == '1');
        refresh_status_shm(true);
        snprintf(reply, sizeof(reply), "{\"ok\":true,\"mode\":\"%s\"}\n",
                 g_shadow_mode ? "shadow" : "enforce");
    } else if (strcmp(cmd, "PING") == 0) {
        refresh_status_shm(true);
        snprintf(reply, sizeof(reply), "{\"ok\":true,\"version\":\"%s\",\"mode\":\"%s\"}\n",
                 HSHIELD_VERSION, g_shadow_mode ? "shadow" : "enforce");
    }

    if (write(cfd, reply, strlen(reply)) < 0) {}
    close(cfd);
}

static int run_daemon(int argc, char **argv) {
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--shadow") == 0) g_shadow_mode = true;
        else if (strcmp(argv[i], "--no-fanotify") == 0) g_disable_fanotify = true;
        else if (strcmp(argv[i], "--sock") == 0 && i + 1 < argc) g_ctrl_sock_path = argv[++i];
        else if (strcmp(argv[i], "--status-shm") == 0 && i + 1 < argc) g_status_shm_path = argv[++i];
        else if (strcmp(argv[i], "--rules-shm") == 0 && i + 1 < argc) g_rules_shm_path = argv[++i];
        else if (strcmp(argv[i], "--rules-json") == 0 && i + 1 < argc) g_rules_json_path = argv[++i];
        else if (strcmp(argv[i], "--forensics-dir") == 0 && i + 1 < argc) g_forensics_dir = argv[++i];
        else if (strcmp(argv[i], "--quarantine-dir") == 0 && i + 1 < argc) g_quarantine_dir = argv[++i];
    }

    if (geteuid() != 0) {
        fprintf(stderr, "hshield --daemon requires root (CAP_NET_ADMIN + CAP_SYS_ADMIN)\n");
        return 1;
    }

    signal(SIGTERM, on_sigterm);
    signal(SIGINT, on_sigterm);
    signal(SIGCHLD, SIG_IGN); /* Auto-reap async ZeroMemory / nft children */

    g_boot_ts = (uint64_t)time(NULL);
    mkdir_p(g_quarantine_dir, 0755, USER_UID, USER_GID);
    mkdir_p(g_forensics_dir, 0755, USER_UID, USER_GID);
    (void)ensure_quarantine_key();

    if (!init_rules_shm(true)) {
        fprintf(stderr, "hshield: failed to initialize %s\n", g_rules_shm_path);
        return 1;
    }
    load_rules_json_into_shm();
    if (!g_shadow_mode) {
        init_nftables_shield();
    }

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    int nl_fd = setup_cn_proc_netlink();
    int fan_fd = g_disable_fanotify ? -1 : setup_fanotify_canaries();
    int ino_fd = setup_inotify_persistence();
    g_ino_fd_global = ino_fd;
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    int ctrl_fd = setup_control_socket();

    if (epfd < 0 || nl_fd < 0 || (!g_disable_fanotify && fan_fd < 0) || ino_fd < 0 || tfd < 0 || ctrl_fd < 0) {
        fprintf(stderr, "hshield: kernel subsystem init failed (nl=%d fan=%d ino=%d tfd=%d ctrl=%d)\n",
                nl_fd, fan_fd, ino_fd, tfd, ctrl_fd);
        return 1;
    }

    int fds[5] = {nl_fd, fan_fd, ino_fd, tfd, ctrl_fd};
    for (int i = 0; i < 5; i++) {
        if (fds[i] < 0) continue;
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        ev.data.fd = fds[i];
        (void)epoll_ctl(epfd, EPOLL_CTL_ADD, fds[i], &ev);
    }

    refresh_status_shm(true);
    fprintf(stderr, "[hshield v%s] General Immunity Daemon ACTIVE (mode=%s, CN_PROC + fanotify + inotify + nftables)\n",
            HSHIELD_VERSION, g_shadow_mode ? "SHADOW" : "ENFORCE");

    struct epoll_event events[16];
    while (!g_stop) {
        /* Infinite sleep (`-1`) when idle -> literally 0.000% idle CPU! */
        int n = epoll_wait(epfd, events, 16, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        /* Always drain CN_PROC exec radar and inotify integrity events FIRST */
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (fd == nl_fd) handle_cn_proc_events(nl_fd, tfd);
            else if (fd == ino_fd) handle_inotify_events(ino_fd);
        }
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (fan_fd >= 0 && fd == fan_fd) handle_fanotify_events(fan_fd);
            else if (fd == tfd) handle_micro_inspect_timer(tfd);
            else if (fd == ctrl_fd) handle_control_client(ctrl_fd, ino_fd, fan_fd);
        }
    }

    refresh_status_shm(false);
    unlink(g_ctrl_sock_path);
    close(ctrl_fd);
    close(tfd);
    close(ino_fd);
    if (fan_fd >= 0) close(fan_fd);
    close(nl_fd);
    close(epfd);
    return 0;
}

/* =========================================================================
 * Linux Landlock LSM Preventive Sandbox (`hshield sandbox`) — 0.00% CPU
 * ========================================================================= */
static int ll_create_ruleset(const void *attr, size_t size, uint32_t flags) {
    return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static int ll_add_rule(int ruleset_fd, enum landlock_rule_type rule_type, const void *rule_attr, uint32_t flags) {
    return (int)syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}

static int ll_restrict_self(int ruleset_fd, uint32_t flags) {
    return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

static void landlock_allow_path(int rfd, const char *path, uint64_t access_mask) {
    int pfd = open(path, O_PATH | O_CLOEXEC);
    if (pfd < 0) return;
    struct stat st;
    if (fstat(pfd, &st) == 0 && !S_ISDIR(st.st_mode)) {
        /* File-only access rights when target is not a directory */
        access_mask &= (LANDLOCK_ACCESS_FS_EXECUTE |
                        LANDLOCK_ACCESS_FS_WRITE_FILE |
                        LANDLOCK_ACCESS_FS_READ_FILE |
                        LANDLOCK_ACCESS_FS_TRUNCATE |
                        LANDLOCK_ACCESS_FS_IOCTL_DEV);
    }
    if (access_mask != 0) {
        struct landlock_path_beneath_attr pba;
        memset(&pba, 0, sizeof(pba));
        pba.allowed_access = access_mask;
        pba.parent_fd = pfd;
        (void)ll_add_rule(rfd, LANDLOCK_RULE_PATH_BENEATH, &pba, 0);
    }
    close(pfd);
}

static bool is_sensitive_home_entry(const char *name) {
    static const char *blocked[] = {
        ".ssh", ".gnupg", ".claude", ".claude.json", ".codex", ".gemini",
        ".opencodex", ".netrc", ".aws", ".kube", ".pki", ".docker",
        ".bash_history", ".zsh_history", ".python_history", NULL
    };
    for (int i = 0; blocked[i]; i++) {
        if (strcmp(name, blocked[i]) == 0) return true;
    }
    return false;
}

static bool is_sensitive_config_entry(const char *name) {
    static const char *blocked[] = {
        "hephaestus", "google-chrome", "chromium", "Codex", "gh", "hub", "systemd", NULL
    };
    for (int i = 0; blocked[i]; i++) {
        if (strcmp(name, blocked[i]) == 0) return true;
    }
    return false;
}

static int cmd_sandbox(int argc, char **argv) {
    const char *allow_write_dir = NULL;
    int cmd_idx = -1;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--allow-write") == 0 && i + 1 < argc) {
            allow_write_dir = argv[++i];
        } else if (strcmp(argv[i], "--") == 0) {
            cmd_idx = i + 1;
            break;
        } else if (argv[i][0] != '-') {
            cmd_idx = i;
            break;
        }
    }
    if (cmd_idx < 0 || cmd_idx >= argc) {
        fprintf(stderr, "Usage: hshield sandbox [--allow-write <dir>] -- <cmd...>\n");
        return 2;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return 1;
    }

    int abi = ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) {
        fprintf(stderr, "hshield sandbox: Landlock LSM unavailable on this kernel\n");
        return 1;
    }

    uint64_t fs_ro = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    uint64_t fs_rw = fs_ro | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
                     LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR |
                     LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                     LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_SYM;
    if (abi >= 2) fs_rw |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) fs_rw |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) {
        fs_ro |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
        fs_rw |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }

    int rfd = -1;
    if (abi >= 6) {
        struct ll_ruleset_abi_v6 attr6;
        memset(&attr6, 0, sizeof(attr6));
        attr6.handled_access_fs = fs_rw;
        attr6.scoped = LANDLOCK_SCOPE_SIGNAL | LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;
        rfd = ll_create_ruleset(&attr6, sizeof(attr6), 0);
    }
    if (rfd < 0) {
        struct ll_ruleset_abi_v1 attr1;
        memset(&attr1, 0, sizeof(attr1));
        attr1.handled_access_fs = fs_rw;
        rfd = ll_create_ruleset(&attr1, sizeof(attr1), 0);
    }
    if (rfd < 0) {
        perror("landlock_create_ruleset");
        return 1;
    }

    /* 1. Read-Only OS & Persistence Paths (0 write access to /etc, /usr, /var/spool/cron!) */
    const char *ro_sys[] = {"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/proc", "/sys", "/run", NULL};
    for (int i = 0; ro_sys[i]; i++) {
        /* Note: /opt/google/chrome binaries are safe RO, user profile is in ~/.config/google-chrome (blocked!) */
        landlock_allow_path(rfd, ro_sys[i], fs_ro);
    }

    /* 2. Safe Scratch / Device Paths */
    landlock_allow_path(rfd, "/tmp", fs_rw);
    landlock_allow_path(rfd, "/dev", fs_rw);

    /* 3. Selective $HOME Enumeration: completely omit secrets & make shell RC files Read-Only! */
    const char *home = getenv("HOME");
    if (!home || !home[0]) home = USER_HOME;
    DIR *hd = opendir(home);
    if (hd) {
        struct dirent *de;
        while ((de = readdir(hd)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
            if (is_sensitive_home_entry(de->d_name)) continue;
            char sub[1024];
            snprintf(sub, sizeof(sub), "%.500s/%.500s", home, de->d_name);
            if (strcmp(de->d_name, ".config") == 0) {
                DIR *cd = opendir(sub);
                if (cd) {
                    struct dirent *cde;
                    while ((cde = readdir(cd)) != NULL) {
                        if (strcmp(cde->d_name, ".") == 0 || strcmp(cde->d_name, "..") == 0) continue;
                        if (is_sensitive_config_entry(cde->d_name)) continue;
                        char csub[1024];
                        snprintf(csub, sizeof(csub), "%.500s/%.500s", sub, cde->d_name);
                        landlock_allow_path(rfd, csub, fs_ro);
                    }
                    closedir(cd);
                }
            } else {
                /* Read-only by default inside $HOME (protects .bashrc, .profile, projects unless --allow-write) */
                landlock_allow_path(rfd, sub, fs_ro);
            }
        }
        closedir(hd);
    }

    if (allow_write_dir && allow_write_dir[0]) {
        char real_w[PATH_MAX];
        const char *wp = realpath(allow_write_dir, real_w) ? real_w : allow_write_dir;
        if (!strstr(wp, "/.ssh") && !strstr(wp, "/.gnupg") &&
            !strstr(wp, "/hephaestus/vault") && !strstr(wp, "/google-chrome")) {
            landlock_allow_path(rfd, wp, fs_rw);
        }
    }

    if (ll_restrict_self(rfd, 0) != 0) {
        perror("landlock_restrict_self");
        close(rfd);
        return 1;
    }
    close(rfd);

    execvp(argv[cmd_idx], &argv[cmd_idx]);
    perror("execvp");
    return 127;
}

/* =========================================================================
 * Repo-Trap & MCP Cryptographic Pin Auditor (`hshield audit`)
 * ========================================================================= */
static bool check_file_for_prompt_trap(const char *path, char *finding_out, size_t cap) {
    char buf[16384];
    ssize_t n = read_file_fast(path, buf, sizeof(buf));
    if (n <= 0) return false;

    /* Check invisible zero-width / bidi trojan-source Unicode sequences */
    for (ssize_t i = 0; i + 2 < n; i++) {
        unsigned char b0 = (unsigned char)buf[i];
        unsigned char b1 = (unsigned char)buf[i + 1];
        unsigned char b2 = (unsigned char)buf[i + 2];
        if (b0 == 0xE2 && b1 == 0x80 &&
            (b2 == 0x8B || b2 == 0x8C || b2 == 0x8D || (b2 >= 0xAA && b2 <= 0xAE))) {
            snprintf(finding_out, cap, "zero_width_or_bidi_trojan_unicode");
            return true;
        }
    }

    /* Case-insensitive scan for prompt injection / rogue hook execution */
    char low[16384];
    for (ssize_t i = 0; i < n; i++) low[i] = (char)tolower((unsigned char)buf[i]);
    low[n] = '\0';

    const char *bad_patterns[] = {
        "ignore previous instructions",
        "ignore all previous instructions",
        "disregard security",
        "guvenlik kurallarini yoksay",
        "güvenlik kurallarını yoksay",
        "curl ", "wget ", "nc -e", "/dev/tcp/",
        "base64 -d", "eval(", "hvault", ".ssh/id_",
        NULL
    };
    for (int i = 0; bad_patterns[i]; i++) {
        if (strstr(low, bad_patterns[i])) {
            snprintf(finding_out, cap, "suspicious_directive:%s", bad_patterns[i]);
            return true;
        }
    }
    return false;
}

static bool is_trusted_own_workspace(const char *real_dir) {
    return (strcmp(real_dir, "/home/user") == 0 ||
            strncmp(real_dir, "/opt/hshield-trusted", 37) == 0 ||
            strncmp(real_dir, "/opt/protected-workloads", 26) == 0);
}

static int cmd_audit(int argc, char **argv) {
    bool json = false;
    const char *target_dir = ".";
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0) json = true;
        else if (argv[i][0] != '-') target_dir = argv[i];
    }

    char real_dir[PATH_MAX];
    if (!realpath(target_dir, real_dir)) snprintf(real_dir, sizeof(real_dir), "%.1024s", target_dir);
    bool trusted_ws = is_trusted_own_workspace(real_dir);

    int issues = 0;
    char findings[4096] = {0};
    size_t f_used = 0;

    /* 1. Verify MCP SHA-256 Pin (`/etc/hephaestus/mcp_pins.json`) */
    bool mcp_pin_ok = false;
    char pin_buf[2048];
    if (read_file_fast(ETC_MCP_PINS_PATH, pin_buf, sizeof(pin_buf)) > 0) {
        uint8_t mcp_sha[32];
        if (sha256_file("/usr/local/bin/hephaestus-mcp", mcp_sha)) {
            char mcp_hex[65];
            bytes_to_hex(mcp_sha, 32, mcp_hex);
            if (strstr(pin_buf, mcp_hex) != NULL) {
                mcp_pin_ok = true;
            } else {
                issues++;
                f_used += (size_t)snprintf(findings + f_used, sizeof(findings) - f_used,
                                           "chameleon_mcp_hash_mismatch(/usr/local/bin/hephaestus-mcp); ");
            }
        }
    }

    /* 2. Scan target repository for Repo Traps (`.mcp.json`, `.claude*`, `.codex*`, `.gemini*`, `AGENTS.md`) */
    const char *trap_candidates[] = {
        ".mcp.json",
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".codex/config.toml",
        ".gemini/settings.json",
        "AGENTS.md",
        "CLAUDE.md",
        "GEMINI.md",
        NULL
    };

    for (int i = 0; trap_candidates[i]; i++) {
        char p[1536];
        snprintf(p, sizeof(p), "%.1000s/%s", real_dir, trap_candidates[i]);
        struct stat st;
        if (stat(p, &st) != 0) continue;

        /* Untrusted repo defining `.mcp.json` or local `.claude/settings*` hooks is an immediate Repo Trap! */
        if (!trusted_ws && (strcmp(trap_candidates[i], ".mcp.json") == 0 ||
                            strncmp(trap_candidates[i], ".claude/", 8) == 0 ||
                            strncmp(trap_candidates[i], ".codex/", 7) == 0 ||
                            strncmp(trap_candidates[i], ".gemini/", 8) == 0)) {
            issues++;
            if (f_used + 160 < sizeof(findings)) {
                f_used += (size_t)snprintf(findings + f_used, sizeof(findings) - f_used,
                                           "untrusted_repo_agent_trap:%s; ", trap_candidates[i]);
            }
            /* Strip execute bits and quarantine/neutralize `.mcp.json` in untrusted scratch/download repos */
            if (is_untrusted_origin_path(real_dir) && strcmp(trap_candidates[i], ".mcp.json") == 0) {
                char disabled[1600];
                snprintf(disabled, sizeof(disabled), "%.1500s.blocked_by_hshield", p);
                (void)rename(p, disabled);
            }
            continue;
        }

        char trap_detail[160] = {0};
        if (!trusted_ws && check_file_for_prompt_trap(p, trap_detail, sizeof(trap_detail))) {
            issues++;
            if (f_used + 200 < sizeof(findings)) {
                f_used += (size_t)snprintf(findings + f_used, sizeof(findings) - f_used,
                                           "prompt_injection_trap(%s:%s); ", trap_candidates[i], trap_detail);
            }
        }
    }

    /* 3. Persistence Integrity Check (`/etc/ld.so.preload`) */
    struct stat lst;
    if (stat("/etc/ld.so.preload", &lst) == 0 && lst.st_size > 0) {
        issues++;
        if (f_used + 96 < sizeof(findings)) {
            f_used += (size_t)snprintf(findings + f_used, sizeof(findings) - f_used,
                                       "non_empty_etc_ld_so_preload; ");
        }
    }

    if (json) {
        char dir_e[1200], find_e[4200];
        json_escape(real_dir, dir_e, sizeof(dir_e));
        json_escape(findings, find_e, sizeof(find_e));
        printf("{\"ok\":%s,\"dir\":\"%s\",\"trusted_workspace\":%s,\"mcp_pin_verified\":%s,"
               "\"issues\":%d,\"findings\":\"%s\"}\n",
               (issues == 0) ? "true" : "false",
               dir_e,
               trusted_ws ? "true" : "false",
               mcp_pin_ok ? "true" : "false",
               issues,
               find_e);
    } else {
        printf("[hshield audit] dir=%s trusted=%s mcp_pin=%s issues=%d\n",
               real_dir, trusted_ws ? "yes" : "no", mcp_pin_ok ? "SEALED" : "UNPINNED/MISMATCH", issues);
        if (issues > 0) {
            printf("  FINDINGS: %s\n", findings);
        }
    }
    return (issues == 0) ? 0 : 1;
}

/* =========================================================================
 * Client Control Helpers (`status`, `quarantine`, `evolve`, `restore`, `watch`)
 * ========================================================================= */
static bool send_ctrl_command(const char *msg, char *reply_out, size_t cap) {
    int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sfd < 0) return false;
    struct sockaddr_un su;
    memset(&su, 0, sizeof(su));
    su.sun_family = AF_UNIX;
    snprintf(su.sun_path, sizeof(su.sun_path), "%s", g_ctrl_sock_path);
    if (connect(sfd, (struct sockaddr *)&su, sizeof(su)) != 0) {
        close(sfd);
        return false;
    }
    if (write(sfd, msg, strlen(msg)) < 0) {
        close(sfd);
        return false;
    }
    if (reply_out && cap > 0) {
        ssize_t n = read(sfd, reply_out, cap - 1);
        if (n > 0) reply_out[n] = '\0';
        else reply_out[0] = '\0';
    }
    close(sfd);
    return true;
}

static int cmd_status(bool json) {
    char reply[128];
    (void)send_ctrl_command("PING\n", reply, sizeof(reply));

    char buf[2048];
    if (read_file_fast(g_status_shm_path, buf, sizeof(buf)) <= 0) {
        if (json) {
            printf("{\"active\":false,\"quarantined\":%d,\"immune_rules\":0}\n", count_quarantine_files());
        } else {
            printf("[SHIELD: INACTIVE | Quarantined: %d | Immune Rules: 0]\n", count_quarantine_files());
        }
        return 1;
    }
    if (json) {
        fputs(buf, stdout);
        return 0;
    }

    bool active = (strstr(buf, "\"active\":true") != NULL);
    bool shadow = (strstr(buf, "\"mode\":\"shadow\"") != NULL);
    int qcnt = count_quarantine_files();
    unsigned int rules = 0, inc = 0, cblk = 0, fblk = 0, frest = 0;
    unsigned long long fus = 0;
    char *p;
    if ((p = strstr(buf, "\"immune_rules\":"))) rules = (unsigned int)strtoul(p + 15, NULL, 10);
    if ((p = strstr(buf, "\"incidents_total\":"))) inc = (unsigned int)strtoul(p + 18, NULL, 10);
    if ((p = strstr(buf, "\"canary_blocks\":"))) cblk = (unsigned int)strtoul(p + 16, NULL, 10);
    if ((p = strstr(buf, "\"immune_fast_blocks\":"))) fblk = (unsigned int)strtoul(p + 21, NULL, 10);
    if ((p = strstr(buf, "\"files_restored\":"))) frest = (unsigned int)strtoul(p + 17, NULL, 10);
    if ((p = strstr(buf, "\"last_freeze_us\":"))) fus = strtoull(p + 17, NULL, 10);

    printf("[SHIELD: %s | Quarantined: %d | Immune Rules: %u]\n",
           active ? (shadow ? "SHADOW" : "ACTIVE") : "INACTIVE", qcnt, rules);
    printf("  Incidents: %u | Canary Blocks: %u | <0.1ms Antibody Hits: %u | CoW Restored: %u | Last Freeze: %lluus\n",
           inc, cblk, fblk, frest, fus);
    return active ? 0 : 1;
}

static int cmd_quarantine(int argc, char **argv) {
    const char *sub = (argc >= 3) ? argv[2] : "list";
    if (strcmp(sub, "inspect") == 0 && argc >= 4) {
        char p[640], buf[8192];
        snprintf(p, sizeof(p), "%s/%.200s.json", g_quarantine_dir, argv[3]);
        if (read_file_fast(p, buf, sizeof(buf)) > 0) {
            fputs(buf, stdout);
            return 0;
        }
        fprintf(stderr, "Quarantine ID not found: %s\n", argv[3]);
        return 1;
    }
    /* Static quarantine intake from `horganize` or CLI: `hshield quarantine add <file> <reason>` */
    if (strcmp(sub, "add") == 0 && argc >= 4) {
        const char *fpath = argv[3];
        const char *reason = (argc >= 5) ? argv[4] : "static_supply_chain_gate";
        mkdir_p(g_quarantine_dir, 0755, USER_UID, USER_GID);

        uint8_t sha[32] = {0};
        if (!sha256_file(fpath, sha)) {
            fprintf(stderr, "hshield quarantine add: cannot read %s\n", fpath);
            return 1;
        }
        char sha_hex[65];
        bytes_to_hex(sha, 32, sha_hex);

        char qid[96], qdest[640], qmeta[640];
        snprintf(qid, sizeof(qid), "qstatic_%lld_%.12s", (long long)time(NULL), sha_hex);
        snprintf(qdest, sizeof(qdest), "%s/%s.qenc", g_quarantine_dir, qid);
        snprintf(qmeta, sizeof(qmeta), "%s/%s.json", g_quarantine_dir, qid);

        /* Encrypt if root, else move stripped 0400 file into .qenc slot */
        bool encrypted = false;
        if (geteuid() == 0) {
            encrypted = quarantine_encrypt_file(fpath, qdest, sha);
            if (encrypted) (void)unlink(fpath);
        }
        if (!encrypted) {
            (void)chmod(fpath, 0400);
            if (rename(fpath, qdest) != 0) {
                /* Cross-filesystem fallback */
                char *cp_cmd[] = {"/usr/bin/cp", "-f", (char *)fpath, qdest, NULL};
                if (run_cmd_quiet(cp_cmd) == 0) {
                    (void)chmod(qdest, 0400);
                    (void)unlink(fpath);
                }
            }
        }

        char fp_e[640], r_e[256];
        json_escape(fpath, fp_e, sizeof(fp_e));
        json_escape(reason, r_e, sizeof(r_e));
        char meta[1536];
        int mlen = snprintf(
            meta, sizeof(meta),
            "{\n  \"incident_id\": \"%s\",\n  \"ts\": %" PRIu64 ",\n"
            "  \"trigger\": \"%s\",\n  \"original_path\": \"%s\",\n"
            "  \"sha256\": \"%s\",\n  \"quarantine_file\": \"%s\"\n}\n",
            qid, (uint64_t)time(NULL), r_e, fp_e, sha_hex, qdest
        );
        if (mlen > 0) (void)write_file_atomic(qmeta, meta, (size_t)mlen, 0644);

        /* Evolve antibody rule automatically */
        char ctrl[512], rep[256];
        snprintf(ctrl, sizeof(ctrl), "EVOLVE\t%s\t-\t%.120s\n", sha_hex, reason);
        (void)send_ctrl_command(ctrl, rep, sizeof(rep));

        printf("{\"ok\":true,\"id\":\"%s\",\"sha256\":\"%s\",\"quarantine\":\"%s\"}\n",
               qid, sha_hex, qdest);
        return 0;
    }

    DIR *d = opendir(g_quarantine_dir);
    if (!d) {
        printf("Quarantine empty (0 items).\n");
        return 0;
    }
    int cnt = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t l = strlen(de->d_name);
        if (l > 5 && strcmp(de->d_name + l - 5, ".json") == 0) {
            char p[640], buf[2048];
            snprintf(p, sizeof(p), "%s/%.250s", g_quarantine_dir, de->d_name);
            if (read_file_fast(p, buf, sizeof(buf)) > 0) {
                char trig[128] = "?", sha[70] = "?";
                char *tp = strstr(buf, "\"trigger\": \"");
                if (tp) {
                    tp += 12;
                    size_t k = 0;
                    while (tp[k] && tp[k] != '"' && k + 1 < sizeof(trig)) { trig[k] = tp[k]; k++; }
                    trig[k] = '\0';
                }
                char *sp = strstr(buf, "\"sha256\": \"");
                if (sp) {
                    sp += 11;
                    size_t k = 0;
                    while (sp[k] && sp[k] != '"' && k + 1 < sizeof(sha)) { sha[k] = sp[k]; k++; }
                    sha[k] = '\0';
                }
                printf("  [%.*s] trigger=%s sha256=%.16s...\n", (int)(l - 5), de->d_name, trig, sha);
                cnt++;
            }
        }
    }
    closedir(d);
    printf("Total quarantined items: %d\n", cnt);
    return 0;
}

static int cmd_evolve(int argc, char **argv) {
    const char *sha_hex = NULL;
    const char *pattern = NULL;
    const char *reason = "manual-antibody";
    const char *file_path = NULL;
    char computed_hex[65] = {0};

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--sha256") == 0 && i + 1 < argc) sha_hex = argv[++i];
        else if (strcmp(argv[i], "--pattern") == 0 && i + 1 < argc) pattern = argv[++i];
        else if (strcmp(argv[i], "--reason") == 0 && i + 1 < argc) reason = argv[++i];
        else if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) file_path = argv[++i];
    }

    if (file_path) {
        uint8_t digest[32];
        if (!sha256_file(file_path, digest)) {
            fprintf(stderr, "hshield evolve: failed to hash %s\n", file_path);
            return 1;
        }
        bytes_to_hex(digest, 32, computed_hex);
        sha_hex = computed_hex;
    }

    if (!sha_hex && !pattern) {
        fprintf(stderr, "Usage: hshield evolve [--file <path> | --sha256 <hex>] [--pattern <pat>] [--reason <r>]\n");
        return 2;
    }

    char msg[512], reply[256] = {0};
    snprintf(msg, sizeof(msg), "EVOLVE\t%.64s\t%.124s\t%.92s\n",
             sha_hex ? sha_hex : "-",
             pattern ? pattern : "-",
             reason);

    if (send_ctrl_command(msg, reply, sizeof(reply)) && reply[0]) {
        fputs(reply, stdout);
        return 0;
    }

    /* Offline fallback if daemon not running and caller is root */
    if (geteuid() == 0 && init_rules_shm(true)) {
        load_rules_json_into_shm();
        uint8_t sha[32];
        const uint8_t *sp = (sha_hex && hex_to_bytes(sha_hex, sha, 32)) ? sha : NULL;
        bool ok = add_immune_rule(sp, pattern, reason);
        printf("{\"ok\":%s,\"rules\":%u}\n", ok ? "true" : "false", g_rules_shm->count);
        return ok ? 0 : 1;
    }
    fprintf(stderr, "hshield evolve: daemon socket %s unreachable\n", g_ctrl_sock_path);
    return 1;
}

static int cmd_restore(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: hshield restore <path...>\n");
        return 2;
    }
    char *args[64];
    int k = 0;
    args[k++] = "/usr/local/bin/hrollback";
    args[k++] = "restore-file";
    for (int i = 2; i < argc && k < 62; i++) {
        args[k++] = argv[i];
    }
    args[k] = NULL;
    execvp(args[0], args);
    perror("execvp(hrollback)");
    return 127;
}

static int cmd_watch(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: hshield watch <abs_path>\n");
        return 2;
    }
    char real_p[PATH_MAX];
    const char *p = realpath(argv[2], real_p) ? real_p : argv[2];
    char msg[600], reply[256] = {0};
    snprintf(msg, sizeof(msg), "WATCH\t%.500s\n", p);
    if (!send_ctrl_command(msg, reply, sizeof(reply))) {
        fprintf(stderr, "hshield watch: daemon unreachable\n");
        return 1;
    }
    fputs(reply, stdout);
    return 0;
}

static int cmd_eval_pid(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: hshield eval-pid <pid> [--shadow]\n");
        return 2;
    }
    pid_t pid = (pid_t)atoi(argv[2]);
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--shadow") == 0) g_shadow_mode = true;
    }
    uint64_t t_eval0 = mono_ns();
    ProcMeta pm;
    if (!read_proc_meta(pid, &pm)) {
        printf("{\"ok\":false,\"error\":\"proc_not_found\"}\n");
        return 1;
    }
    bool sacred = is_sacred_core(&pm);
    PendingInspect slot;
    memset(&slot, 0, sizeof(slot));
    slot.pid = pid;
    WxAssessment wx;
    bool hit = (!sacred) && assess_wx_injection(&pm, &slot, t_eval0, &wx);
    printf("{\"ok\":true,\"pid\":%d,\"uid\":%u,\"sacred\":%s,\"hit\":%s,"
           "\"score\":%d,\"confidence\":\"%s\",\"reason\":\"%s\",\"summary\":\"%s\"}\n",
           (int)pid, (unsigned)pm.uid, sacred ? "true" : "false", hit ? "true" : "false",
           wx.risk_score,
           (wx.confidence == CONF_HIGH) ? "high" : (wx.confidence == CONF_MEDIUM) ? "medium" : "none",
           wx.reason, wx.summary);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "eval-pid") == 0) return cmd_eval_pid(argc, argv);
    if (argc < 2 || strcmp(argv[1], "status") == 0) {
        bool json = false;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0) json = true;
            else if (strcmp(argv[i], "--sock") == 0 && i + 1 < argc) g_ctrl_sock_path = argv[++i];
            else if (strcmp(argv[i], "--status-shm") == 0 && i + 1 < argc) g_status_shm_path = argv[++i];
            else if (strcmp(argv[i], "--quarantine-dir") == 0 && i + 1 < argc) g_quarantine_dir = argv[++i];
        }
        return cmd_status(json);
    }
    if (strcmp(argv[1], "--daemon") == 0) return run_daemon(argc, argv);
    if (strcmp(argv[1], "sandbox") == 0) return cmd_sandbox(argc, argv);
    if (strcmp(argv[1], "audit") == 0) return cmd_audit(argc, argv);
    if (strcmp(argv[1], "quarantine") == 0) return cmd_quarantine(argc, argv);
    if (strcmp(argv[1], "evolve") == 0) return cmd_evolve(argc, argv);
    if (strcmp(argv[1], "restore") == 0) return cmd_restore(argc, argv);
    if (strcmp(argv[1], "watch") == 0) return cmd_watch(argc, argv);

    printf("hshield v%s — Zero-Overhead Kernel & Cognitive General Immunity Layer\n"
           "Usage:\n"
           "  hshield status [--json]                      Show live immunity status & counters\n"
           "  hshield sandbox [--allow-write DIR] -- CMD   Run CMD inside 0%%-CPU Landlock LSM armor\n"
           "  hshield audit [DIR] [--json]                 Verify MCP pins & scan repo for AI traps\n"
           "  hshield quarantine [list|inspect ID|add F R] Manage AES-256-GCM quarantine vault\n"
           "  hshield evolve [--file F|--sha256 H|--pattern P] [--reason R]\n"
           "  hshield restore <PATH...>                    <30ms Btrfs CoW surgical file repair\n"
           "  hshield watch <PATH>                         Register file/dir for auto-CoW repair\n"
           "  hshield --daemon [--shadow]                  Start root immunity daemon (enforce or shadow)\n",
           HSHIELD_VERSION);
    return 0;
}
