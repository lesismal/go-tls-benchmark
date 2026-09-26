/*
 * The uSockets TLS echo server: uSockets - the event loops and TLS under
 * uWebSockets and Bun - with BoringSSL, one event loop per CPU, each
 * listening on every benchmark port with SO_REUSEPORT and writing back
 * whatever plaintext a connection reads, from the loop's read callback.
 *
 * It takes the Go servers' flags and serves what they serve: the variant -f
 * names, pinned to its TLS version, on its fifty benchmark ports, with a
 * certificate of the -key type issued at startup, and the control routes the
 * clients read its pid, CPU and memory from on the port after them.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <libproc.h>
#include <mach/mach_time.h>
#endif

#include <openssl/bn.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "libusockets.h"

/* This server's variants in config.Variants: name, TLS version, first and
 * last benchmark port. config's TestCTablesMatch holds this to the Go table. */
static const struct variant {
    const char *name, *version;
    int first, last;
} VARIANTS[] = {
    {"usockets-tls11", "1.1", 12801, 12850},
    {"usockets-tls12", "1.2", 12901, 12950},
    {"usockets-tls13", "1.3", 13001, 13050},
};

/* config.ServerName: what the certificate is issued to. */
#define SERVER_NAME "go-tls-benchmark"

/* fib/tls's DefaultHandshakeTimeout, which the other servers use too. */
#define HANDSHAKE_TIMEOUT_SECONDS 10

static struct {
    const char *framework;
    int nodelay, reuseport;
    const char *key;
} flags = {"usockets-tls13", 1, 1, "ecdsa"};

static void usage(const char *err) {
    if (err && *err) fprintf(stderr, "%s\n", err);
    fprintf(stderr,
            "Usage of usockets.server:\n"
            "  -f value\n    \tframework: the variant to run, usockets-tls11, usockets-tls12 or usockets-tls13 (default \"usockets-tls13\")\n"
            "  -nodelay\n    \ttcp nodelay (default true)\n"
            "  -reuseport\n    \treuse port (default true)\n"
            "  -b value\n    \texpected message size, ignored: reads go into each loop's own buffer\n"
            "  -m value\n    \tmemory limit, ignored: there is no GC to limit\n"
            "  -key value\n    \tcertificate key: ecdsa (P-256), rsa (2048) or ed25519 (default \"ecdsa\")\n");
    exit(2);
}

static int parse_bool(const char *name, const char *v) {
    if (!v) return 1;
    if (!strcmp(v, "1") || !strcmp(v, "t") || !strcmp(v, "T") || !strcmp(v, "true") || !strcmp(v, "TRUE") || !strcmp(v, "True")) return 1;
    if (!strcmp(v, "0") || !strcmp(v, "f") || !strcmp(v, "F") || !strcmp(v, "false") || !strcmp(v, "FALSE") || !strcmp(v, "False")) return 0;
    char msg[256];
    snprintf(msg, sizeof msg, "invalid boolean value \"%s\" for -%s", v, name);
    usage(msg);
    return 0;
}

/* The Go servers' flags, in Go's flag syntax: -name=value or -name value, and
 * a bool flag on its own for true. One they do not define stops the server,
 * as it stops a Go one. */
static void parse_flags(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (arg[0] != '-') break;
        arg += arg[1] == '-' ? 2 : 1;
        char name[64];
        const char *value = NULL;
        char *eq = strchr(arg, '=');
        size_t n = eq ? (size_t)(eq - arg) : strlen(arg);
        if (n >= sizeof name) usage("flag name too long");
        memcpy(name, arg, n);
        name[n] = 0;
        if (eq) value = eq + 1;
        int boolean = !strcmp(name, "nodelay") || !strcmp(name, "reuseport");
        if (!strcmp(name, "h") || !strcmp(name, "help")) usage(NULL);
        if (!boolean && !value) {
            if (i + 1 >= argc) {
                char msg[128];
                snprintf(msg, sizeof msg, "flag needs an argument: -%s", name);
                usage(msg);
            }
            value = argv[++i];
        }
        if (!strcmp(name, "nodelay")) flags.nodelay = parse_bool(name, value);
        else if (!strcmp(name, "reuseport")) flags.reuseport = parse_bool(name, value);
        else if (!strcmp(name, "f")) flags.framework = value;
        else if (!strcmp(name, "key")) flags.key = value;
        else if (!strcmp(name, "b") || !strcmp(name, "m")) {}
        else {
            char msg[128];
            snprintf(msg, sizeof msg, "flag provided but not defined: -%s", name);
            usage(msg);
        }
    }
}

/* ---- The certificate ---------------------------------------------------- */

/* A self-signed certificate for SERVER_NAME with a new key of the -key type,
 * as package certs issues the Go servers theirs, written as PEM to two
 * temporary files for uSockets to load. */
static int self_signed(const char *key, char *cert_path, char *key_path) {
    EVP_PKEY *pkey = NULL;
    if (!strcmp(key, "ecdsa")) {
        EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ec || !EC_KEY_generate_key(ec)) return -1;
        pkey = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(pkey, ec);
    } else if (!strcmp(key, "rsa")) {
        RSA *rsa = RSA_new();
        BIGNUM *e = BN_new();
        BN_set_word(e, RSA_F4);
        if (!RSA_generate_key_ex(rsa, 2048, e, NULL)) return -1;
        BN_free(e);
        pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, rsa);
    } else if (!strcmp(key, "ed25519")) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
        if (!ctx || EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &pkey) != 1) return -1;
        EVP_PKEY_CTX_free(ctx);
    } else {
        fprintf(stderr, "unsupported certificate key \"%s\", want ecdsa, rsa or ed25519\n", key);
        return -1;
    }

    X509 *x = X509_new();
    X509_set_version(x, X509_VERSION_3);
    uint64_t serial;
    RAND_bytes((uint8_t *)&serial, sizeof serial);
    ASN1_INTEGER_set_uint64(X509_get_serialNumber(x), serial >> 2);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 365L * 24 * 3600);
    X509_NAME *name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const uint8_t *)SERVER_NAME, -1, -1, 0);
    X509_set_issuer_name(x, name);
    X509_set_pubkey(x, pkey);
    X509_EXTENSION *san = X509V3_EXT_nconf_nid(NULL, NULL, NID_subject_alt_name,
                                               "DNS:" SERVER_NAME ",DNS:localhost,IP:127.0.0.1");
    if (!san) return -1;
    X509_add_ext(x, san, -1);
    X509_EXTENSION_free(san);
    /* Ed25519 signs the message itself, with no separate digest. */
    const EVP_MD *md = EVP_PKEY_id(pkey) == EVP_PKEY_ED25519 ? NULL : EVP_sha256();
    if (!X509_sign(x, pkey, md)) return -1;

    strcpy(cert_path, "/tmp/usockets-cert-XXXXXX");
    strcpy(key_path, "/tmp/usockets-key-XXXXXX");
    int cfd = mkstemp(cert_path), kfd = mkstemp(key_path);
    if (cfd < 0 || kfd < 0) return -1;
    FILE *cf = fdopen(cfd, "w"), *kf = fdopen(kfd, "w");
    int ok = PEM_write_X509(cf, x) && PEM_write_PrivateKey(kf, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(cf);
    fclose(kf);
    X509_free(x);
    EVP_PKEY_free(pkey);
    return ok ? 0 : -1;
}

/* ---- Echo --------------------------------------------------------------- */

/* What a connection has read but not yet managed to write back. SSL_write
 * that could not finish has to be retried with the same bytes, so they are
 * kept, in order, until the socket takes them; a connection whose writes keep
 * up never allocates one. */
struct conn {
    char *pending;
    int len, cap;
};

static int tls_version;

static struct us_socket_t *on_open(struct us_socket_t *s, int is_client, char *ip, int ip_length) {
    (void)is_client, (void)ip, (void)ip_length;
    struct conn *c = us_socket_ext(1, s);
    memset(c, 0, sizeof *c);
    /* The descriptor, whichever layer asks: a TLS socket starts with the
     * TCP one. */
    int fd = (int)(intptr_t)us_socket_get_native_handle(0, s);
    int nodelay = flags.nodelay;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof nodelay);
    us_socket_timeout(1, s, HANDSHAKE_TIMEOUT_SECONDS);
    return s;
}

/* The timer bounds the handshake only: one that has completed is left open
 * however long it is idle, as the other servers leave theirs. */
static struct us_socket_t *on_timeout(struct us_socket_t *s) {
    SSL *ssl = us_socket_get_native_handle(1, s);
    if (ssl && SSL_is_init_finished(ssl)) return s;
    return us_socket_close(1, s, 0, NULL);
}

static void keep(struct conn *c, const char *data, int length) {
    if (c->len + length > c->cap) {
        int cap = c->cap ? c->cap : 16 << 10;
        while (cap < c->len + length) cap *= 2;
        c->pending = realloc(c->pending, cap);
        c->cap = cap;
    }
    memcpy(c->pending + c->len, data, length);
    c->len += length;
}

/* Writes back what is pending, as much as the socket takes. */
static struct us_socket_t *flush(struct us_socket_t *s, struct conn *c) {
    if (!c->len) return s;
    int written = us_socket_write(1, s, c->pending, c->len, 0);
    if (written > 0) {
        memmove(c->pending, c->pending + written, c->len - written);
        c->len -= written;
    }
    if (!c->len && c->cap > (64 << 10)) {
        /* A burst grew it past what is worth keeping for the connection. */
        free(c->pending);
        c->pending = NULL;
        c->cap = 0;
    }
    return s;
}

static struct us_socket_t *on_data(struct us_socket_t *s, char *data, int length) {
    struct conn *c = us_socket_ext(1, s);
    if (c->len) {
        /* Behind what is already waiting, to keep the stream in order. */
        keep(c, data, length);
        return flush(s, c);
    }
    int written = us_socket_write(1, s, data, length, 0);
    if (written < length) keep(c, data + (written > 0 ? written : 0), length - (written > 0 ? written : 0));
    return s;
}

static struct us_socket_t *on_writable(struct us_socket_t *s) {
    return flush(s, us_socket_ext(1, s));
}

static struct us_socket_t *on_close(struct us_socket_t *s, int code, void *reason) {
    (void)code, (void)reason;
    struct conn *c = us_socket_ext(1, s);
    free(c->pending);
    c->pending = NULL;
    return s;
}

static struct us_socket_t *on_end(struct us_socket_t *s) {
    return us_socket_close(1, s, 0, NULL);
}

/* ---- Process samples, for /ps ------------------------------------------- */

/* User and system CPU time this process has used, in seconds. */
static int cpu_seconds(double *out) {
#ifdef __APPLE__
    struct proc_taskinfo info;
    if (proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &info, sizeof info) != sizeof info) return -1;
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    *out = (double)(info.pti_total_user + info.pti_total_system) * tb.numer / tb.denom / 1e9;
    return 0;
#else
    FILE *f = fopen("/proc/self/stat", "r");
    if (!f) return -1;
    char buf[1024];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    /* Past the parenthesized comm, which may hold spaces: state is field 3
     * overall, utime and stime 14 and 15. */
    char *p = strrchr(buf, ')');
    if (!p) return -1;
    unsigned long long utime, stime;
    if (sscanf(p + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %llu %llu", &utime, &stime) != 2) return -1;
    *out = (double)(utime + stime) / sysconf(_SC_CLK_TCK);
    return 0;
#endif
}

static uint64_t rss_bytes(void) {
#ifdef __APPLE__
    struct proc_taskinfo info;
    if (proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &info, sizeof info) != sizeof info) return 0;
    return info.pti_resident_size;
#else
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    uint64_t kb = 0;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "VmRSS:", 6)) {
            kb = strtoull(line + 6, NULL, 10);
            break;
        }
    }
    fclose(f);
    return kb * 1024;
#endif
}

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* The samples /init starts and /ps answers with, in the shape
 * github.com/lesismal/perf's PSCounter marshals to - the "cpu" and
 * "mem"[].rss fields, which are all the clients read. */
static struct {
    pthread_mutex_t mu;
    int started;
    double *cpu;
    uint64_t *rss;
    size_t n, cap;
    uint64_t interval_ns;
} sampler = {PTHREAD_MUTEX_INITIALIZER, 0, NULL, NULL, 0, 0, 0};

static void *sample(void *arg) {
    (void)arg;
    double last_cpu = 0, last_at = now_seconds();
    cpu_seconds(&last_cpu);
    for (;;) {
        struct timespec ts = {sampler.interval_ns / 1000000000ULL, sampler.interval_ns % 1000000000ULL};
        nanosleep(&ts, NULL);
        double cpu = last_cpu, at = now_seconds();
        cpu_seconds(&cpu);
        double percent = at > last_at ? (cpu - last_cpu) / (at - last_at) * 100 : 0;
        last_cpu = cpu, last_at = at;
        uint64_t rss = rss_bytes();
        pthread_mutex_lock(&sampler.mu);
        if (sampler.n == sampler.cap) {
            sampler.cap = sampler.cap ? sampler.cap * 2 : 256;
            sampler.cpu = realloc(sampler.cpu, sampler.cap * sizeof *sampler.cpu);
            sampler.rss = realloc(sampler.rss, sampler.cap * sizeof *sampler.rss);
        }
        sampler.cpu[sampler.n] = percent;
        sampler.rss[sampler.n] = rss;
        sampler.n++;
        pthread_mutex_unlock(&sampler.mu);
    }
    return NULL;
}

/* Once, however many times /init arrives, as the Go servers guard theirs: a
 * client that retried the request can deliver it twice. */
static void start_sampler(uint64_t interval_ns) {
    pthread_mutex_lock(&sampler.mu);
    int started = sampler.started;
    sampler.started = 1;
    pthread_mutex_unlock(&sampler.mu);
    if (started) return;
    sampler.interval_ns = interval_ns ? interval_ns : 1000000000ULL;
    pthread_t t;
    pthread_create(&t, NULL, sample, NULL);
    pthread_detach(t);
}

/* The JSON /ps answers with, malloc'd. */
static char *ps_json(void) {
    pthread_mutex_lock(&sampler.mu);
    size_t cap = 64 + sampler.n * 64, len = 0;
    char *out = malloc(cap);
    len += snprintf(out + len, cap - len, "{\"cpu\":[");
    for (size_t i = 0; i < sampler.n; i++)
        len += snprintf(out + len, cap - len, "%s%.6f", i ? "," : "", sampler.cpu[i]);
    len += snprintf(out + len, cap - len, "],\"mem\":[");
    for (size_t i = 0; i < sampler.n; i++)
        len += snprintf(out + len, cap - len, "%s{\"rss\":%" PRIu64 "}", i ? "," : "", sampler.rss[i]);
    snprintf(out + len, cap - len, "]}");
    pthread_mutex_unlock(&sampler.mu);
    return out;
}

/* ---- The control routes ------------------------------------------------- */

/* The Go servers' frameworks.HandleCommon, on the port after the benchmark
 * ones, in plaintext: POST /init and GET /ps, one request per connection. */
struct control {
    char buf[8192];
    int len;
};

static struct us_socket_t *control_open(struct us_socket_t *s, int is_client, char *ip, int ip_length) {
    (void)is_client, (void)ip, (void)ip_length;
    ((struct control *)us_socket_ext(0, s))->len = 0;
    return s;
}

static struct us_socket_t *control_data(struct us_socket_t *s, char *data, int length) {
    struct control *c = us_socket_ext(0, s);
    if (c->len + length >= (int)sizeof c->buf) return us_socket_close(0, s, 0, NULL);
    memcpy(c->buf + c->len, data, length);
    c->len += length;
    c->buf[c->len] = 0;
    char *end = strstr(c->buf, "\r\n\r\n");
    if (!end) return s;
    int head = (int)(end - c->buf) + 4;
    int content_length = 0;
    for (char *p = c->buf; p < end; p++) {
        if ((p == c->buf || p[-1] == '\n') && !strncasecmp(p, "content-length:", 15)) {
            content_length = atoi(p + 15);
        }
    }
    if (c->len < head + content_length) return s;

    char method[16] = {0}, path[256] = {0};
    sscanf(c->buf, "%15s %255s", method, path);
    char *q = strchr(path, '?');
    if (q) *q = 0;
    const char *status = "200 OK", *type = "text/plain; charset=utf-8";
    char *body = NULL;
    if (!strcmp(method, "POST") && !strcmp(path, "/init")) {
        /* The body encoding/json makes of config.InitArgs,
         * {"PsInterval":1000000000}. */
        uint64_t interval = 0;
        char *at = strstr(c->buf + head, "PsInterval");
        if (at && (at = strchr(at, ':'))) interval = strtoull(at + 1, NULL, 10);
        start_sampler(interval);
        body = malloc(32);
        snprintf(body, 32, "%d", (int)getpid());
    } else if (!strcmp(method, "GET") && !strcmp(path, "/ps")) {
        type = "application/json";
        body = ps_json();
    } else {
        status = "404 Not Found";
        body = strdup("404 page not found\n");
    }
    size_t body_len = strlen(body), cap = body_len + 256;
    char *response = malloc(cap);
    int n = snprintf(response, cap,
                     "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     status, type, body_len, body);
    /* Small enough for a socket buffer, in the one write. */
    us_socket_write(0, s, response, n, 0);
    free(response);
    free(body);
    us_socket_shutdown(0, s);
    return s;
}

static struct us_socket_t *control_end(struct us_socket_t *s) {
    return us_socket_close(0, s, 0, NULL);
}

static struct us_socket_t *control_close(struct us_socket_t *s, int code, void *reason) {
    (void)code, (void)reason;
    return s;
}

static struct us_socket_t *control_writable(struct us_socket_t *s) {
    return s;
}

static struct us_socket_t *control_timeout(struct us_socket_t *s) {
    return s;
}

/* ---- Loops -------------------------------------------------------------- */

static const struct variant *variant;
static char cert_path[64], key_path[64];

static void on_wakeup(struct us_loop_t *loop) { (void)loop; }
static void on_pre(struct us_loop_t *loop) { (void)loop; }
static void on_post(struct us_loop_t *loop) { (void)loop; }

/* What the other servers' TLS libraries do by default, set to match: the
 * post-quantum X25519MLKEM768 key exchange first, then X25519, for TLS 1.3;
 * one session ticket after a TLS 1.3 handshake, stateless, as crypto/tls
 * issues; no server-side session cache, which crypto/tls does not keep. The
 * cipher suite is picked from the client's order, which every client here
 * begins with AES-128-GCM - or, for TLS 1.1, AES-128-CBC-SHA. */
static int configure(SSL_CTX *ctx) {
    if (!SSL_CTX_set_min_proto_version(ctx, tls_version) || !SSL_CTX_set_max_proto_version(ctx, tls_version)) {
        fprintf(stderr, "%s: cannot pin the TLS version\n", variant->name);
        return -1;
    }
    if (!SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519:P-256:P-384")) {
        fprintf(stderr, "%s: cannot set the key exchange groups\n", variant->name);
        return -1;
    }
    SSL_CTX_set_num_tickets(ctx, 1);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    return 0;
}

/* Counts the loops that are listening, so that main says the server is up
 * only once all of them are: a latch, as macOS has no pthread barrier. */
static struct {
    pthread_mutex_t mu;
    pthread_cond_t cond;
    int left;
} ready = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0};

struct loop_args {
    int index;
};

static void *run_loop(void *arg) {
    struct loop_args *a = arg;
    struct us_loop_t *loop = us_create_loop(NULL, on_wakeup, on_pre, on_post, 0);
    struct us_socket_context_options_t options = {0};
    options.cert_file_name = cert_path;
    options.key_file_name = key_path;
    /* The context carries nothing of its own: what each connection carries
     * is sized by listen, below. */
    struct us_socket_context_t *ctx = us_create_socket_context(1, loop, 0, options);
    if (!ctx || configure(us_socket_context_get_native_handle(1, ctx))) {
        fprintf(stderr, "%s: creating the TLS context failed\n", variant->name);
        exit(1);
    }
    us_socket_context_on_open(1, ctx, on_open);
    us_socket_context_on_data(1, ctx, on_data);
    us_socket_context_on_writable(1, ctx, on_writable);
    us_socket_context_on_close(1, ctx, on_close);
    us_socket_context_on_timeout(1, ctx, on_timeout);
    us_socket_context_on_end(1, ctx, on_end);

    /* Every loop listens on every port, and the kernel spreads the
     * connections over them with SO_REUSEPORT, which uSockets sets on every
     * listener by default. */
    for (int port = variant->first; port <= variant->last; port++) {
        if (!us_socket_context_listen(1, ctx, NULL, port, LIBUS_LISTEN_DEFAULT, sizeof(struct conn))) {
            fprintf(stderr, "%s: listen on port %d failed: %s\n", variant->name, port, strerror(errno));
            exit(1);
        }
    }

    if (a->index == 0) {
        struct us_socket_context_options_t none = {0};
        struct us_socket_context_t *control = us_create_socket_context(0, loop, 0, none);
        us_socket_context_on_open(0, control, control_open);
        us_socket_context_on_data(0, control, control_data);
        us_socket_context_on_end(0, control, control_end);
        us_socket_context_on_close(0, control, control_close);
        us_socket_context_on_writable(0, control, control_writable);
        us_socket_context_on_timeout(0, control, control_timeout);
        if (!us_socket_context_listen(0, control, NULL, variant->last + 1, LIBUS_LISTEN_DEFAULT, sizeof(struct control))) {
            fprintf(stderr, "%s: listen on control port %d failed: %s\n", variant->name, variant->last + 1, strerror(errno));
            exit(1);
        }
    }
    pthread_mutex_lock(&ready.mu);
    if (--ready.left == 0) pthread_cond_signal(&ready.cond);
    pthread_mutex_unlock(&ready.mu);
    us_loop_run(loop);
    return NULL;
}

/* The CPUs this process may run on: sched_getaffinity where there is one,
 * since script/env.sh pins the server with taskset and the online count
 * ignores the mask. */
static int cpus(void) {
#ifdef __linux__
    cpu_set_t set;
    if (!sched_getaffinity(0, sizeof set, &set)) return CPU_COUNT(&set);
#endif
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
}

static void on_signal(int sig) {
    (void)sig;
    unlink(cert_path);
    unlink(key_path);
    _exit(0);
}

int main(int argc, char **argv) {
    parse_flags(argc, argv);
    for (size_t i = 0; i < sizeof VARIANTS / sizeof *VARIANTS; i++) {
        if (!strcmp(VARIANTS[i].name, flags.framework)) variant = &VARIANTS[i];
    }
    if (!variant) {
        fprintf(stderr, "-f=%s: not a variant of usockets, want one of [usockets-tls11 usockets-tls12 usockets-tls13]\n",
                flags.framework);
        return 1;
    }
    tls_version = !strcmp(variant->version, "1.1") ? TLS1_1_VERSION
                  : !strcmp(variant->version, "1.2") ? TLS1_2_VERSION
                                                     : TLS1_3_VERSION;
    if (self_signed(flags.key, cert_path, key_path)) {
        fprintf(stderr, "%s: issuing the certificate failed\n", variant->name);
        return 1;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    /* One loop per CPU, or one when the ports cannot be shared. */
    int loops = flags.reuseport ? cpus() : 1;
    fprintf(stderr, "%s server: nodelay=%d, reuseport=%d, tls=%s, key=%s, event loops=%d\n", variant->name,
            flags.nodelay, flags.reuseport, variant->version, flags.key, loops);

    ready.left = loops;
    pthread_t *threads = calloc(loops, sizeof *threads);
    struct loop_args *args = calloc(loops, sizeof *args);
    for (int i = 0; i < loops; i++) {
        args[i] = (struct loop_args){i};
        pthread_create(&threads[i], NULL, run_loop, &args[i]);
    }
    pthread_mutex_lock(&ready.mu);
    while (ready.left > 0) pthread_cond_wait(&ready.cond, &ready.mu);
    pthread_mutex_unlock(&ready.mu);
    /* Every context has loaded them by now. */
    unlink(cert_path);
    unlink(key_path);
    fprintf(stderr, "%s server: listening on %d ports, :%d to :%d\n", variant->name, variant->last - variant->first + 1,
            variant->first, variant->last);
    for (int i = 0; i < loops; i++) pthread_join(threads[i], NULL);
    return 0;
}
