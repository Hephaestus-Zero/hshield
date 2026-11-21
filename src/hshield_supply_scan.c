/*
 * hshield_supply_scan.c — Zero-Extract ML Checkpoint & Archive Supply-Chain Gate
 *
 * Performs static, zero-execution inspection of untrusted artifacts before load:
 *   1. Python Pickle VM bytecode analysis (Protocols 0..5): detects dangerous
 *      `GLOBAL` / `INST` / `STACK_GLOBAL` + `REDUCE` deserialization chains
 *      (`os.system`, `posix.system`, `subprocess.Popen`, `builtins.eval`, `pty.spawn`, etc.)
 *      without importing Python or invoking `pickle.loads`.
 *   2. Zero-extract in-RAM `zlib` ZIP Central Directory inspection for PyTorch
 *      checkpoints (`.pt`, `.pth`, `.ckpt`, `.bin`) and source archives:
 *      inflates embedded `*.pkl` streams in bounded memory and flags embedded
 *      AI coding-agent configuration traps (`.mcp.json`, `.claude/settings*`).
 *   3. File-type spoofing & dropper heuristics: ELF binaries disguised under
 *      document/image extensions, deceptive double extensions (`report.pdf.sh`),
 *      and obfuscated base64 / `/dev/tcp` reverse-shell droppers.
 *
 * Build:
 *   gcc -std=c11 -O3 -Wall -Wextra -Werror -o hshield-supply-scan src/hshield_supply_scan.c -lz
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  data[64];
    size_t   datalen;
} Sha256Ctx;

static const uint32_t SHA256_K[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_transform(Sha256Ctx *ctx, const uint8_t data[64]) {
    uint32_t m[64];
    for (int i = 0, j = 0; i < 16; i++, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(m[i - 15], 7) ^ ROR32(m[i - 15], 18) ^ (m[i - 15] >> 3);
        uint32_t s1 = ROR32(m[i - 2], 17) ^ ROR32(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + SHA256_K[i] + m[i];
        uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(Sha256Ctx *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667U; ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U; ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU; ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU; ctx->state[7] = 0x5be0cd19U;
}

static void sha256_update(Sha256Ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final_hex(Sha256Ctx *ctx, char hex_out[65]) {
    size_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    for (int k = 0; k < 8; k++) {
        ctx->data[63 - k] = (uint8_t)(ctx->bitlen >> (k * 8));
    }
    sha256_transform(ctx, ctx->data);
    for (int w = 0; w < 8; w++) {
        snprintf(hex_out + (w * 8), 9, "%08x", ctx->state[w]);
    }
    hex_out[64] = '\0';
}

static bool sha256_file_hex(const char *path, char hex_out[65]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    Sha256Ctx ctx;
    sha256_init(&ctx);
    uint8_t buf[32768];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        sha256_update(&ctx, buf, (size_t)n);
    }
    close(fd);
    if (n < 0) return false;
    sha256_final_hex(&ctx, hex_out);
    return true;
}

static void ext_lower_of(const char *name, char *out, size_t cap) {
    const char *dot = strrchr(name, '.');
    if (!dot || dot == name || !dot[1]) {
        out[0] = '\0';
        return;
    }
    size_t i = 0;
    for (const char *p = dot + 1; *p && i + 1 < cap; p++, i++) {
        out[i] = (char)tolower((unsigned char)*p);
    }
    out[i] = '\0';
}

static void json_escape(const char *src, char *dst, size_t cap) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 6 < cap; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            dst[j++] = '\\';
            dst[j++] = (char)c;
        } else if (c == '\n') {
            dst[j++] = '\\';
            dst[j++] = 'n';
        } else if (c == '\r') {
            dst[j++] = '\\';
            dst[j++] = 'r';
        } else if (c == '\t') {
            dst[j++] = '\\';
            dst[j++] = 't';
        } else if (c >= 0x20) {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
}

#define HSHIELD_SUPPLY_SCAN_VERSION "0.2.1"
#define ZIP_MAX_COMPRESSED_SCAN     (2U * 1024U * 1024U)
#define ZIP_MAX_INFLATE_SCAN        (1024U * 1024U)

static bool match_short_pickle_mod(const uint8_t *buf, size_t len, const char *mod, uint8_t mlen) {
    uint8_t short_u[16];
    if ((size_t)mlen + 2U <= sizeof(short_u)) {
        short_u[0] = 0x8c;
        short_u[1] = mlen;
        memcpy(short_u + 2, mod, mlen);
        if (memmem(buf, len, short_u, (size_t)mlen + 2) != NULL) return true;
    }
    uint8_t bin_u[16];
    if ((size_t)mlen + 4U <= sizeof(bin_u)) {
        bin_u[0] = mlen; bin_u[1] = 0; bin_u[2] = 0; bin_u[3] = 0;
        memcpy(bin_u + 4, mod, mlen);
        if (memmem(buf, len, bin_u, (size_t)mlen + 4) != NULL) return true;
    }
    char p0[16];
    int n0 = snprintf(p0, sizeof(p0), "c%s\n", mod);
    if (n0 > 0 && memmem(buf, len, p0, (size_t)n0) != NULL) return true;
    int n1 = snprintf(p0, sizeof(p0), "i%s\n", mod);
    if (n1 > 0 && memmem(buf, len, p0, (size_t)n1) != NULL) return true;
    int n2 = snprintf(p0, sizeof(p0), "S'%s'", mod);
    if (n2 > 0 && memmem(buf, len, p0, (size_t)n2) != NULL) return true;
    return false;
}

static bool scan_pickle_stream_for_rce(const uint8_t *buf, size_t len, char *why, size_t wcap) {
    if (!buf || len < 6) return false;

    static const char *const proto0_sigs[] = {
        "cos\nsystem", "cposix\nsystem", "cnt\nsystem",
        "cos\npopen", "cposix\npopen", "cnt\npopen", "csubprocess\n",
        "cbuiltins\neval", "cbuiltins\nexec", "cbuiltins\n__import__",
        "c__builtin__\neval", "c__builtin__\nexec", "c__builtin__\n__import__",
        "cimportlib\nimport_module", "coperator\nattrgetter",
        "cwebbrowser\nopen", "cpty\nspawn",
        "ios\nsystem", "iposix\nsystem", "ios\npopen", "iposix\npopen",
        "isubprocess\n", "ibuiltins\neval", "ibuiltins\nexec", NULL
    };
    for (int i = 0; proto0_sigs[i]; i++) {
        size_t sl = strlen(proto0_sigs[i]);
        if (memmem(buf, len, proto0_sigs[i], sl) != NULL) {
            snprintf(why, wcap, "pickle-rce-proto0:%s", proto0_sigs[i]);
            for (size_t k = 0; why[k]; k++) { if (why[k] == '\n') why[k] = '.'; }
            return true;
        }
    }

    const char *exec_op = NULL;
    if (memchr(buf, 'R', len) != NULL) exec_op = "REDUCE";
    else if (memchr(buf, 0x81, len) != NULL) exec_op = "NEWOBJ";
    else if (memchr(buf, 0x92, len) != NULL) exec_op = "NEWOBJ_EX";
    else if (memchr(buf, 'b', len) != NULL) exec_op = "BUILD";
    else if (memchr(buf, 'o', len) != NULL) exec_op = "OBJ";
    else if (memchr(buf, 'i', len) != NULL) exec_op = "INST";

    bool looks_pickle = (buf[0] == 0x80 && buf[1] >= 2 && buf[1] <= 5) ||
                        (memchr(buf, 0x93, len) != NULL && exec_op != NULL) ||
                        (memchr(buf, 'c', len) != NULL && exec_op != NULL);
    if (!looks_pickle || !exec_op) return false;

    static const char *const bad_mods[] = {
        "posix", "subprocess", "builtins", "__builtin__", "pty", "runpy", "commands",
        "importlib", "operator", "ctypes", "marshal", "webbrowser", "shutil", NULL
    };
    static const char *const bad_fns[] = {
        "system", "popen", "Popen", "check_output", "check_call", "call",
        "eval", "exec", "compile", "spawn", "__import__", "import_module",
        "attrgetter", "getattr", "loads", "open", "rmtree", "unlink", NULL
    };

    const char *hit_mod = NULL;
    for (int i = 0; bad_mods[i]; i++) {
        if (memmem(buf, len, bad_mods[i], strlen(bad_mods[i])) != NULL) {
            hit_mod = bad_mods[i];
            break;
        }
    }
    if (!hit_mod && match_short_pickle_mod(buf, len, "os", 2)) hit_mod = "os";
    if (!hit_mod && match_short_pickle_mod(buf, len, "nt", 2)) hit_mod = "nt";
    if (!hit_mod && match_short_pickle_mod(buf, len, "sys", 3)) hit_mod = "sys";
    if (!hit_mod && match_short_pickle_mod(buf, len, "pip", 3)) hit_mod = "pip";
    if (!hit_mod && match_short_pickle_mod(buf, len, "code", 4)) hit_mod = "code";
    if (!hit_mod) return false;

    for (int j = 0; bad_fns[j]; j++) {
        if (memmem(buf, len, bad_fns[j], strlen(bad_fns[j])) != NULL) {
            snprintf(why, wcap, "pickle-rce-opcode:%s.%s+%s", hit_mod, bad_fns[j], exec_op);
            return true;
        }
    }
    return false;
}
static bool scan_zip_for_pickle_or_repotrap(int fd, off_t fsize, char *why, size_t wcap) {
    off_t tail_sz = (fsize > 65558) ? 65558 : fsize;
    uint8_t *tail = malloc((size_t)tail_sz);
    if (!tail) return false;
    ssize_t tr = pread(fd, tail, (size_t)tail_sz, fsize - tail_sz);
    if (tr < 22) { free(tail); return false; }

    ssize_t eocd = -1;
    for (ssize_t i = tr - 22; i >= 0; i--) {
        if (tail[i] == 'P' && tail[i + 1] == 'K' && tail[i + 2] == 5 && tail[i + 3] == 6) {
            eocd = i;
            break;
        }
    }
    if (eocd < 0) { free(tail); return false; }

    uint16_t cd_entries = (uint16_t)(tail[eocd + 10] | (tail[eocd + 11] << 8));
    uint32_t cd_size    = (uint32_t)tail[eocd + 12] | ((uint32_t)tail[eocd + 13] << 8) |
                          ((uint32_t)tail[eocd + 14] << 16) | ((uint32_t)tail[eocd + 15] << 24);
    uint32_t cd_off     = (uint32_t)tail[eocd + 16] | ((uint32_t)tail[eocd + 17] << 8) |
                          ((uint32_t)tail[eocd + 18] << 16) | ((uint32_t)tail[eocd + 19] << 24);
    free(tail);

    if (cd_size == 0 || cd_size > 2 * 1024 * 1024 || (off_t)cd_off + (off_t)cd_size > fsize) {
        return false;
    }
    uint8_t *cd = malloc(cd_size);
    if (!cd) return false;
    if (pread(fd, cd, cd_size, (off_t)cd_off) != (ssize_t)cd_size) {
        free(cd);
        return false;
    }

    bool malicious = false;
    size_t pos = 0;
    for (uint16_t e = 0; e < cd_entries && pos + 46 <= cd_size && !malicious; e++) {
        if (memcmp(cd + pos, "PK\x01\x02", 4) != 0) break;
        uint16_t method = (uint16_t)(cd[pos + 10] | (cd[pos + 11] << 8));
        uint32_t csize  = (uint32_t)cd[pos + 20] | ((uint32_t)cd[pos + 21] << 8) |
                          ((uint32_t)cd[pos + 22] << 16) | ((uint32_t)cd[pos + 23] << 24);
        uint16_t fnlen  = (uint16_t)(cd[pos + 28] | (cd[pos + 29] << 8));
        uint16_t exlen  = (uint16_t)(cd[pos + 30] | (cd[pos + 31] << 8));
        uint16_t cmlen  = (uint16_t)(cd[pos + 32] | (cd[pos + 33] << 8));
        uint32_t lhoff  = (uint32_t)cd[pos + 42] | ((uint32_t)cd[pos + 43] << 8) |
                          ((uint32_t)cd[pos + 44] << 16) | ((uint32_t)cd[pos + 45] << 24);

        if (pos + 46 + fnlen > cd_size) break;
        char entry[256];
        size_t nl = (fnlen < sizeof(entry) - 1) ? fnlen : (sizeof(entry) - 1);
        memcpy(entry, cd + pos + 46, nl);
        entry[nl] = '\0';

        bool is_pkl = (nl > 4 && (strcmp(entry + nl - 4, ".pkl") == 0 ||
                                  (nl > 7 && strcmp(entry + nl - 7, ".pickle") == 0)));
        bool is_mcp_trap = (strstr(entry, ".mcp.json") != NULL ||
                            strstr(entry, ".claude/settings") != NULL ||
                            strstr(entry, ".codex/config") != NULL ||
                            strstr(entry, ".gemini/settings") != NULL ||
                            strstr(entry, ".cursor/hooks.json") != NULL);

        /* Flag embedded agent/MCP trap paths immediately regardless of entry size or compression */
        if (is_mcp_trap) {
            snprintf(why, wcap, "archive-repo-trap:%.200s", entry);
            malicious = true;
            break;
        }

        if (is_pkl && csize > 0 && (off_t)lhoff + 30 < fsize) {
            uint8_t lh[30];
            if (pread(fd, lh, 30, (off_t)lhoff) == 30 && memcmp(lh, "PK\x03\x04", 4) == 0) {
                uint16_t lfn = (uint16_t)(lh[26] | (lh[27] << 8));
                uint16_t lex = (uint16_t)(lh[28] | (lh[29] << 8));
                off_t data_off = (off_t)lhoff + 30 + lfn + lex;
                if (data_off < fsize) {
                    size_t avail_file = (size_t)(fsize - data_off);
                    size_t read_len = (csize < ZIP_MAX_COMPRESSED_SCAN) ? (size_t)csize : ZIP_MAX_COMPRESSED_SCAN;
                    if (read_len > avail_file) read_len = avail_file;
                    uint8_t *cbuf = malloc(read_len);
                    if (cbuf && pread(fd, cbuf, read_len, data_off) == (ssize_t)read_len) {
                        if (method == 0) {
                            if (scan_pickle_stream_for_rce(cbuf, read_len, why, wcap)) {
                                malicious = true;
                            }
                        } else if (method == 8) {
                            size_t ucap = ZIP_MAX_INFLATE_SCAN;
                            uint8_t *ubuf = malloc(ucap);
                            if (ubuf) {
                                z_stream zs = {0};
                                if (inflateInit2(&zs, -MAX_WBITS) == Z_OK) {
                                    zs.next_in = cbuf;
                                    zs.avail_in = (uInt)read_len;
                                    zs.next_out = ubuf;
                                    zs.avail_out = (uInt)ucap;
                                    (void)inflate(&zs, Z_SYNC_FLUSH);
                                    size_t got = ucap - zs.avail_out;
                                    inflateEnd(&zs);
                                    if (got > 0 && scan_pickle_stream_for_rce(ubuf, got, why, wcap)) {
                                        malicious = true;
                                    }
                                }
                                free(ubuf);
                            }
                        }
                    }
                    free(cbuf);
                }
            }
        }
        pos += 46 + fnlen + exlen + cmlen;
    }
    free(cd);
    return malicious;
}

static bool scan_supply_chain_threat(const char *abs_path, const char *base,
                                     const struct stat *st, char *why, size_t wcap) {
    char ext[32];
    ext_lower_of(base, ext, sizeof(ext));

    static const char *const exec_exts[] = {"sh", "bash", "zsh", "elf", "run", "bin", "py", NULL};
    static const char *const lure_sub[]  = {".pdf.", ".jpg.", ".jpeg.", ".png.", ".docx.", ".xlsx.", ".pptx.", ".mp4.", NULL};
    for (int i = 0; exec_exts[i]; i++) {
        if (strcmp(ext, exec_exts[i]) == 0) {
            for (int j = 0; lure_sub[j]; j++) {
                if (strcasestr(base, lure_sub[j]) != NULL) {
                    snprintf(why, wcap, "deceptive-double-extension:%s", base);
                    return true;
                }
            }
        }
    }

    int fd = open(abs_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    uint8_t buf[65536];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        close(fd);
        return false;
    }
    buf[n] = '\0';

    if (n >= 4 && memcmp(buf, "\x7f""ELF", 4) == 0) {
        static const char *const benign_exts[] = {
            "pdf", "png", "jpg", "jpeg", "gif", "webp", "txt", "md", "csv", "json", "doc", "docx", NULL
        };
        for (int i = 0; benign_exts[i]; i++) {
            if (strcmp(ext, benign_exts[i]) == 0) {
                close(fd);
                snprintf(why, wcap, "disguised-elf-binary-as-%s", ext);
                return true;
            }
        }
    }

    bool is_model_ext = (strcmp(ext, "pt") == 0 || strcmp(ext, "pth") == 0 ||
                         strcmp(ext, "pkl") == 0 || strcmp(ext, "pickle") == 0 ||
                         strcmp(ext, "ckpt") == 0 || strcmp(ext, "bin") == 0);
    if (n >= 4 && memcmp(buf, "PK\x03\x04", 4) == 0) {
        if (scan_zip_for_pickle_or_repotrap(fd, st->st_size, why, wcap)) {
            close(fd);
            return true;
        }
    } else if (is_model_ext || (buf[0] == 0x80 && buf[1] >= 2 && buf[1] <= 5)) {
        if (scan_pickle_stream_for_rce(buf, (size_t)n, why, wcap)) {
            close(fd);
            return true;
        }
    }
    close(fd);

    if (strcmp(ext, "sh") == 0 || strcmp(ext, "bash") == 0 || strcmp(ext, "py") == 0 || strcmp(ext, "install") == 0) {
        const char *s = (const char *)buf;
        if ((strcasestr(s, "base64 -d") || strcasestr(s, "base64 --decode")) &&
            (strstr(s, "| sh") || strstr(s, "| bash") || strstr(s, "|sh") || strstr(s, "|bash") || strstr(s, "eval "))) {
            snprintf(why, wcap, "obfuscated-base64-shell-dropper");
            return true;
        }
        if (strstr(s, "/dev/tcp/") && (strstr(s, "0>&1") || strstr(s, ">&0") || strstr(s, "bash -i"))) {
            snprintf(why, wcap, "embedded-bash-reverse-shell");
            return true;
        }
    }
    return false;
}

int main(int argc, char **argv) {
    bool json = false;
    int threats_found = 0;

    int file_count = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0) {
            json = true;
        } else if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
            printf("hshield-supply-scan v%s\n", HSHIELD_SUPPLY_SCAN_VERSION);
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("hshield-supply-scan v%s — Zero-Import Pickle VM & Archive Supply-Chain Scanner\n"
                   "Usage: hshield-supply-scan [--json] <file...>\n",
                   HSHIELD_SUPPLY_SCAN_VERSION);
            return 0;
        } else {
            file_count++;
        }
    }

    if (file_count == 0) {
        fprintf(stderr, "Usage: hshield-supply-scan [--json] <file...>\n");
        return 2;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0) continue;
        const char *path = argv[i];
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
            fprintf(stderr, "hshield-supply-scan: cannot stat regular file: %s\n", path);
            return 2;
        }
        const char *base = strrchr(path, '/');
        base = base ? (base + 1) : path;

        char sha_hex[65] = {0};
        (void)sha256_file_hex(path, sha_hex);

        char why[256] = {0};
        bool hit = scan_supply_chain_threat(path, base, &st, why, sizeof(why));
        if (hit) threats_found++;

        if (json) {
            char pe[1024], we[512];
            json_escape(path, pe, sizeof(pe));
            json_escape(why, we, sizeof(we));
            printf("{\"path\":\"%s\",\"sha256\":\"%s\",\"malicious\":%s,\"finding\":\"%s\"}\n",
                   pe, sha_hex, hit ? "true" : "false", we);
        } else {
            printf("[%s] %s (sha256=%.16s...)%s%s\n",
                   hit ? "BLOCK" : "CLEAN",
                   path,
                   sha_hex,
                   hit ? " -> " : "",
                   hit ? why : "");
        }
    }
    return (threats_found == 0) ? 0 : 1;
}
