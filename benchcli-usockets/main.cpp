// benchcli-usockets: the benchmark client of benchcli-go, on uSockets event
// loops and BoringSSL rather than Go's runtime and crypto/tls.
//
// It takes the same flags, runs the same three benchmarks the same way, and
// writes the same JSON report files, with "benchcli-usockets" as their
// BenchClient, so the Summary table's Client reads "c-usockets". Turning those
// files into the markdown tables is left to the Go client: script/report.sh
// runs it on whatever any client wrote.
//
// Every thread runs a uSockets loop of its own and owns its share of the
// connections. The sockets are uSockets' plain TCP ones, and TLS is BoringSSL
// driven here through memory BIOs rather than uSockets' own TLS layer: that
// one starts a client handshake only when the application first writes, and
// says nothing when it completes, which is the moment Connections times.
// BoringSSL speaks TLS 1.1 as well, so this client measures every framework.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <csignal>
#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <ifaddrs.h>
#ifdef __linux__
#include <sched.h>
#endif
#ifdef __APPLE__
#include <libproc.h>
#include <mach/mach_time.h>
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

extern "C" {
#include "libusockets.h"
}

namespace {

// ---- Time, logging -------------------------------------------------------

int64_t nowNs() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// The Go client's logging.NowString: "20060102 15:04.05.000".
std::string nowString() {
    timeval tv{};
    gettimeofday(&tv, nullptr);
    tm t{};
    time_t secs = tv.tv_sec;
    localtime_r(&secs, &t);
    char buf[64];
    snprintf(buf, sizeof buf, "%04d%02d%02d %02d:%02d.%02d.%03d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour,
             t.tm_min, t.tm_sec, int(tv.tv_usec / 1000));
    return buf;
}

std::mutex logMu;
__attribute__((format(printf, 1, 2))) void logf(const char *fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof buf, fmt, args);
    va_end(args);
    std::lock_guard<std::mutex> g(logMu);
    fprintf(stderr, "%s %s\n", nowString().c_str(), buf);
}
void logs(const std::string &s) { logf("%s", s.c_str()); }
[[noreturn]] void fatal(const std::string &s) {
    logs(s);
    exit(1);
}
const char *SHORT_LINE = "--------------------------------------------------------------\n";
const char *LONG_LINE =
    "----------------------------------------------------------------------------------------------------\n";

// ---- What the Go client reads from package config -------------------------

// Every framework, as config.Variants lists them: name, language, TLS version,
// and the first and last benchmark port. config's TestCClientTableMatches
// holds this table to the Go one, row for row.
struct Framework {
    const char *name, *lang, *version;
    int first, last;
};
const Framework FRAMEWORKS[] = {
    {"fib-tls11", "go", "1.1", 12001, 12050},
    {"fib-tls12", "go", "1.2", 12101, 12150},
    {"fib-tls13", "go", "1.3", 12201, 12250},
    {"rustls-tls12", "rust", "1.2", 12301, 12350},
    {"rustls-tls13", "rust", "1.3", 12401, 12450},
    {"stdtls-tls11", "go", "1.1", 12501, 12550},
    {"stdtls-tls12", "go", "1.2", 12601, 12650},
    {"stdtls-tls13", "go", "1.3", 12701, 12750},
    {"usockets-tls11", "c", "1.1", 12801, 12850},
    {"usockets-tls12", "c", "1.2", 12901, 12950},
    {"usockets-tls13", "c", "1.3", 13001, 13050},
};

// config.ServerName: the SNI every client sends, whatever address it dials.
const char *SERVER_NAME = "go-tls-benchmark";

const Framework *findFramework(const std::string &name) {
    for (auto &f : FRAMEWORKS)
        if (name == f.name) return &f;
    return nullptr;
}

// ---- Flags ------------------------------------------------------------------

// The Go client's flags, by the same names, with the same defaults, in Go's
// flag syntax: -name=value or -name value, one dash or two, and a bool flag on
// its own for true. The scripts pass one set of flags whichever client they
// built, so every flag benchcli-go defines is defined here, and one that is not
// exits the way Go's flag package does.
struct Flag {
    const char *name;
    bool boolean;
    const char *def, *usage;
};
const Flag FLAGS[] = {
    {"nodelay", true, "true", "tcp nodelay"},
    {"m", false, "4294967296", "memory limit, ignored: no GC to limit"},
    {"reuseport", true, "true", "server only: reuse port, ignored"},
    {"key", false, "ecdsa", "server only: certificate key, ignored; the client reports the one it is served"},
    {"f", false, "stdtls-tls13", "framework: the variant to benchmark, e.g. \"fib-tls13\", whose TLS version is the only one the client offers"},
    {"ip", false, "127.0.0.1", "ip, e.g. \"127.0.0.1\""},
    {"c", false, "10000", "client: num of connections"},
    {"dc", false, "2000", "client: dial concurrency"},
    {"dt", false, "5s", "client: dial timeout, which also bounds the TLS handshake"},
    {"dr", false, "5", "client: dial retry times"},
    {"dri", false, "100ms", "client: dial retry interval"},
    {"b", false, "1024", "benchmark: message size, which the server echoes back"},
    {"check", true, "false", "benchmark: whether to check the validity of the response data"},
    {"pi", false, "1000", "benchmark: ps interval in ms"},
    {"ps", false, "auto", "benchmark: where the server's CPU and MEM samples come from: auto, local or remote"},
    {"tpn", true, "true", "benchmark: whether enable TPN caculation"},
    {"ec", false, "10000", "benchecho: concurrency"},
    {"en", false, "2000000", "benchecho: benchmark times"},
    {"el", false, "0", "benchecho: TPS limitation per second"},
    {"ep", true, "false", "benchecho: generate pprof report"},
    {"epd", false, "5", "benchecho: pprof duration"},
    {"rate", true, "false", "benchpipeline: whether run benchpipeline"},
    {"rc", false, "10000", "benchpipeline: concurrency: how many sending groups the connections are divided into"},
    {"rd", false, "10", "benchpipeline: how long to spend to do the test"},
    {"rr", false, "200", "benchpipeline: how many messages can be sent to 1 conn every second"},
    {"rbs", false, "16384", "benchpipeline: how many bytes of pipelined messages can be written to 1 conn every time, when -rpl is 0"},
    {"rpl", false, "0", "benchpipeline: how many messages are merged into one write to 1 conn, which must divide -rr; 0 takes as many as fit in -rbs bytes"},
    {"rl", false, "0", "benchpipeline: message sending limitation per second"},
    {"rp", true, "false", "benchpipeline: generate pprof report"},
    {"rpd", false, "5", "benchpipeline: pprof duration"},
    {"r", true, "false", "make report: done by the Go client, see script/report.sh"},
    {"preffix", false, "", "report file preffix, e.g. \"1m_connections_\""},
    {"suffix", false, "", "report file suffix, e.g. \"_20060102150405\""},
    {"sort", false, "result", "report row order: \"result\" or \"framework\""},
    {"project", false, "", "what the run benchmarks, the Summary's Project row; ignored: the report step writes it"},
};

[[noreturn]] void usage(const std::string &err) {
    if (!err.empty()) fprintf(stderr, "%s\n", err.c_str());
    fprintf(stderr, "Usage of bench.client (benchcli-usockets):\n");
    for (auto &f : FLAGS)
        fprintf(stderr, "  -%s%s\n    \t%s (default \"%s\")\n", f.name, f.boolean ? "" : " value", f.usage, f.def);
    exit(2);
}

bool parseBool(const std::string &v, bool *out) {
    if (v == "1" || v == "t" || v == "T" || v == "true" || v == "TRUE" || v == "True") return *out = true, true;
    if (v == "0" || v == "f" || v == "F" || v == "false" || v == "FALSE" || v == "False") return *out = false, true;
    return false;
}

// time.ParseDuration: decimal numbers, each with a unit, such as "300ms".
bool parseDuration(const std::string &s, int64_t *out) {
    if (s == "0") return *out = 0, true;
    if (s.empty()) return false;
    double total = 0;
    size_t i = 0;
    while (i < s.size()) {
        size_t j = i;
        while (j < s.size() && (isdigit((unsigned char)s[j]) || s[j] == '.')) j++;
        if (j == i) return false;
        double v = atof(s.substr(i, j - i).c_str());
        size_t k = j;
        while (k < s.size() && !(isdigit((unsigned char)s[k]) || s[k] == '.')) k++;
        std::string unit = s.substr(j, k - j);
        double scale = unit == "ns" ? 1 : unit == "us" || unit == "µs" ? 1e3 : unit == "ms" ? 1e6 : unit == "s" ? 1e9
                       : unit == "m" ? 60e9 : unit == "h" ? 3600e9 : -1;
        if (scale < 0) return false;
        total += v * scale;
        i = k;
    }
    *out = int64_t(total);
    return true;
}

struct Flags {
    std::map<std::string, std::string> v;
    Flags(int argc, char **argv) {
        for (auto &f : FLAGS) v[f.name] = f.def;
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg.empty() || arg[0] != '-') break;  // Go's flag package stops at the first non-flag
            arg.erase(0, arg.rfind("--", 0) == 0 ? 2 : 1);
            std::string name = arg, value;
            bool inline_ = false;
            auto eq = arg.find('=');
            if (eq != std::string::npos) name = arg.substr(0, eq), value = arg.substr(eq + 1), inline_ = true;
            if (name == "h" || name == "help") usage("");
            const Flag *flag = nullptr;
            for (auto &f : FLAGS)
                if (name == f.name) flag = &f;
            if (!flag) usage("flag provided but not defined: -" + name);
            if (!inline_) {
                if (flag->boolean) value = "true";
                else if (i + 1 < argc) value = argv[++i];
                else usage("flag needs an argument: -" + name);
            }
            v[name] = value;
        }
        for (auto &f : FLAGS) {
            auto &value = v[f.name];
            bool b;
            int64_t d;
            if (f.boolean && !parseBool(value, &b)) usage("invalid boolean value \"" + value + "\" for -" + f.name);
            if (!f.boolean && (!strcmp(f.name, "dt") || !strcmp(f.name, "dri")) && !parseDuration(value, &d))
                usage("invalid value \"" + value + "\" for flag -" + f.name);
        }
    }
    std::string str(const char *k) const { return v.at(k); }
    bool boolean(const char *k) const {
        bool b = false;
        parseBool(v.at(k), &b);
        return b;
    }
    int64_t num(const char *k) const {
        auto &s = v.at(k);
        char *end = nullptr;
        long long n = strtoll(s.c_str(), &end, 10);
        if (s.empty() || *end) usage("invalid value \"" + s + "\" for flag -" + k);
        return n;
    }
    int64_t dur(const char *k) const {
        int64_t d = 0;
        parseDuration(v.at(k), &d);
        return d;
    }
};

// ---- Numbers, as github.com/lesismal/perf computes them --------------------

// Calculator's TPS, Min, Avg, Max and TPN over a phase's successes.
struct Calc {
    int64_t success = 0, failed = 0, used = 0;
    std::vector<int64_t> costs;
    void finish() {
        std::sort(costs.begin(), costs.end());
        success = int64_t(costs.size());
    }
    int64_t tps() const { return used > 0 ? int64_t(double(success) / (double(used) / 1e9)) : 0; }
    int64_t min() const { return costs.empty() ? 0 : costs.front(); }
    int64_t max() const { return costs.empty() ? 0 : costs.back(); }
    int64_t avg() const {
        if (costs.empty()) return 0;
        long double sum = 0;
        for (auto c : costs) sum += c;
        return int64_t(sum / costs.size());
    }
    int64_t tpn(int percent) const {
        if (costs.empty()) return 0;
        size_t i = size_t(double(percent) / 100 * costs.size());
        return costs[std::min(i, costs.size() - 1)];
    }
};

// The server's CPU and resident memory samples, as perf.PSCounter's RetCPU and
// RetMEM[].RSS hold them.
struct Samples {
    std::vector<double> cpu;
    std::vector<uint64_t> rss;
};
struct Resources {
    double cpuMin = 0, cpuAvg = 0, cpuMax = 0;
    uint64_t memMin = 0, memAvg = 0, memMax = 0;
};

// What the Go client's Report methods get from a PSCounter, quirks included:
// the first CPU sample is left out of the minimum and the average, and the
// memory average is of every sample but the smallest.
Resources resources(const Samples &s) {
    Resources r;
    auto &cpu = s.cpu;
    if (cpu.size() == 1) r.cpuMin = r.cpuAvg = cpu[0];
    else if (cpu.size() > 1) {
        r.cpuMin = *std::min_element(cpu.begin() + 1, cpu.end());
        double sum = 0;
        for (size_t i = 1; i < cpu.size(); i++) sum += cpu[i];
        r.cpuAvg = sum / double(cpu.size() - 1);
    }
    for (auto c : cpu) r.cpuMax = std::max(r.cpuMax, c);
    auto mem = s.rss;
    std::sort(mem.begin(), mem.end());
    if (mem.size() == 1) r.memMin = r.memAvg = mem[0];
    else if (mem.size() > 1) {
        r.memMin = mem[1];
        long double sum = 0;
        for (size_t i = 1; i < mem.size(); i++) sum += mem[i];
        r.memAvg = uint64_t(sum / (mem.size() - 1));
    }
    if (!mem.empty()) r.memMax = mem.back();
    return r;
}

// report.eer: throughput/cost, or 0 where that is not a finite number.
double eer(double throughput, double cost) {
    if (!(cost > 0) || !std::isfinite(throughput)) return 0;
    double v = throughput / cost;
    return std::isfinite(v) ? v : 0;
}
double cpuEER(double tps, double cpuAvg) { return eer(tps, cpuAvg); }
double memEER(double tps, uint64_t memAvg) { return eer(tps, double(memAvg) / double(1 << 20)); }

// perf.I2TimeString and perf.I2MemString.
std::string timeString(int64_t ns) {
    char b[64];
    if (ns / 1000000000 >= 1) snprintf(b, sizeof b, "%.2fs", ns / 1e9);
    else if (ns / 1000000 >= 1) snprintf(b, sizeof b, "%.2fms", ns / 1e6);
    else if (ns / 1000 >= 1) snprintf(b, sizeof b, "%.2fus", ns / 1e3);
    else snprintf(b, sizeof b, "%lldns", (long long)ns);
    return b;
}
std::string memString(uint64_t bytes) {
    char b[64];
    double gb = double(bytes) / double(1ULL << 30), mb = double(bytes) / double(1 << 20);
    if (gb >= 1) snprintf(b, sizeof b, "%.2fG", gb);
    else if (mb >= 1) snprintf(b, sizeof b, "%.2fM", mb);
    else snprintf(b, sizeof b, "%.2fK", double(bytes) / 1024);
    return b;
}

// ---- Control requests -----------------------------------------------------

std::string urlHost(const std::string &ip) {
    if (ip.find(':') != std::string::npos && ip.front() != '[') return "[" + ip + "]";
    return ip;
}
std::string bareHost(std::string ip) {
    if (!ip.empty() && ip.front() == '[' && ip.back() == ']') ip = ip.substr(1, ip.size() - 2);
    return ip;
}

// One HTTP request to host:port, in HTTP/1.0 so that the reply is never
// chunked: the server answers with a body that ends where the connection
// does. The status, or -1 for a transport failure, and the body.
int httpRequest(const std::string &host, int port, const std::string &method, const std::string &path,
                const std::string &body, int timeoutSeconds, std::string *out, std::string *err) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(bareHost(host).c_str(), std::to_string(port).c_str(), &hints, &res) || !res) {
        *err = "cannot resolve " + host;
        return -1;
    }
    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    timeval tv{timeoutSeconds, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int rc = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (rc) {
        *err = std::string("connect: ") + strerror(errno);
        close(fd);
        return -1;
    }
    std::string req = method + " " + path + " HTTP/1.0\r\nHost: " + urlHost(host) + ":" + std::to_string(port) +
                      "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    size_t off = 0;
    while (off < req.size()) {
        ssize_t n = send(fd, req.data() + off, req.size() - off, 0);
        if (n <= 0) {
            *err = std::string("write: ") + strerror(errno);
            close(fd);
            return -1;
        }
        off += size_t(n);
    }
    std::string reply;
    char buf[16384];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n == 0) break;
        if (n < 0) {
            *err = std::string("read: ") + strerror(errno);
            close(fd);
            return -1;
        }
        reply.append(buf, size_t(n));
    }
    close(fd);
    auto end = reply.find("\r\n\r\n");
    int status = 0;
    if (end == std::string::npos || sscanf(reply.c_str(), "HTTP/%*s %d", &status) != 1) {
        *err = "malformed HTTP response";
        return -1;
    }
    *out = reply.substr(end + 4);
    return status;
}

// config.controlRequest: a transport failure is retried, patiently, since the
// server may be draining the backlog of a phase that has just finished; a
// reply the server produced - a 404 included - is not.
bool control(const Framework &fw, const std::string &ip, const std::string &method, const std::string &path,
             const std::string &body, std::string *out, std::string *err, int attempts = 4) {
    int port = fw.last + 1;
    std::string url = "http://" + urlHost(ip) + ":" + std::to_string(port) + path;
    for (int attempt = 1; attempt <= attempts; attempt++) {
        if (attempt > 1) std::this_thread::sleep_for(std::chrono::seconds(2 * (attempt - 1)));
        std::string e;
        int status = httpRequest(ip, port, method, path, body, 30, out, &e);
        if (status == 200) return true;
        if (status > 0) {
            *err = url + ": " + std::to_string(status) + ": " + *out;
            return false;
        }
        *err = url + ": " + e;
        if (attempt < attempts) logf("control request failed, retrying (%d/%d): %s", attempt, attempts, err->c_str());
    }
    return false;
}

// ---- Where the CPU and MEM columns come from ------------------------------

// A process' user and system CPU time in seconds, and its resident memory,
// read from the operating system: /proc on Linux, proc_pidinfo on macOS.
bool cpuSeconds(int pid, double *out) {
#ifdef __APPLE__
    proc_taskinfo info{};
    if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &info, sizeof info) != sizeof info) return false;
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    *out = double(info.pti_total_user + info.pti_total_system) * tb.numer / tb.denom / 1e9;
    return true;
#else
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char buf[1024];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *p = strrchr(buf, ')');
    unsigned long long utime, stime;
    if (!p || sscanf(p + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %llu %llu", &utime, &stime) != 2)
        return false;
    *out = double(utime + stime) / double(sysconf(_SC_CLK_TCK));
    return true;
#endif
}
bool rssBytes(int pid, uint64_t *out) {
#ifdef __APPLE__
    proc_taskinfo info{};
    if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &info, sizeof info) != sizeof info) return false;
    *out = info.pti_resident_size;
    return true;
#else
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char line[256];
    bool found = false;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "VmRSS:", 6)) {
            *out = strtoull(line + 6, nullptr, 10) * 1024;
            found = true;
            break;
        }
    fclose(f);
    return found;
#endif
}

std::string baseName(const std::string &p) {
    auto i = p.rfind('/');
    return i == std::string::npos ? p : p.substr(i + 1);
}

// pid and the base name of argv[0] for every process this user can see:
// /proc where there is one, ps where there is not.
std::vector<std::pair<int, std::string>> listProcesses() {
    std::vector<std::pair<int, std::string>> out;
    if (DIR *d = opendir("/proc")) {
        while (dirent *e = readdir(d)) {
            int pid = atoi(e->d_name);
            if (pid <= 0) continue;
            char path[64];
            snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
            FILE *f = fopen(path, "r");
            if (!f) continue;
            char buf[4096];
            size_t n = fread(buf, 1, sizeof buf - 1, f);
            fclose(f);
            buf[n] = 0;
            if (n) out.push_back({pid, baseName(buf)});
        }
        closedir(d);
        if (!out.empty()) return out;
    }
    if (FILE *p = popen("ps -o pid=,comm= -A", "r")) {
        char line[4096];
        while (fgets(line, sizeof line, p)) {
            int pid;
            char name[4000];
            if (sscanf(line, " %d %3999[^\n]", &pid, name) == 2) out.push_back({pid, baseName(name)});
        }
        pclose(p);
    }
    return out;
}

// config.FindServerProcess: the one process on this machine named the way
// script/build.sh names the framework's server binary.
int findServer(const std::string &framework, std::string *err) {
    std::string want = framework + ".server";
    std::vector<int> pids;
    for (auto &p : listProcesses())
        if (p.second == want) pids.push_back(p.first);
    if (pids.size() == 1) return pids[0];
    *err = pids.empty() ? "no " + want + " process on this machine"
                        : std::to_string(pids.size()) + " " + want +
                              " processes on this machine: stop the leftovers of earlier runs, e.g. with script/killall.sh";
    return -1;
}

// config.IsLocalHost: the loopback address, or one of this machine's own.
bool isLocalHost(const std::string &host) {
    auto h = bareHost(host);
    if (h.empty()) return false;
    addrinfo hints{}, *res = nullptr;
    if (getaddrinfo(h.c_str(), nullptr, &hints, &res) || !res) return false;
    std::vector<std::string> ips;
    for (auto *a = res; a; a = a->ai_next) {
        char buf[INET6_ADDRSTRLEN];
        if (a->ai_family == AF_INET) {
            auto *in = (sockaddr_in *)a->ai_addr;
            if ((ntohl(in->sin_addr.s_addr) >> 24) == 127 || in->sin_addr.s_addr == 0) return freeaddrinfo(res), true;
            inet_ntop(AF_INET, &in->sin_addr, buf, sizeof buf);
        } else if (a->ai_family == AF_INET6) {
            auto *in6 = (sockaddr_in6 *)a->ai_addr;
            if (IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr) || IN6_IS_ADDR_UNSPECIFIED(&in6->sin6_addr))
                return freeaddrinfo(res), true;
            inet_ntop(AF_INET6, &in6->sin6_addr, buf, sizeof buf);
        } else continue;
        ips.push_back(buf);
    }
    freeaddrinfo(res);
    ifaddrs *ifa = nullptr;
    if (getifaddrs(&ifa)) return false;
    bool local = false;
    for (auto *i = ifa; i && !local; i = i->ifa_next) {
        if (!i->ifa_addr) continue;
        char buf[INET6_ADDRSTRLEN] = {0};
        if (i->ifa_addr->sa_family == AF_INET)
            inet_ntop(AF_INET, &((sockaddr_in *)i->ifa_addr)->sin_addr, buf, sizeof buf);
        else if (i->ifa_addr->sa_family == AF_INET6)
            inet_ntop(AF_INET6, &((sockaddr_in6 *)i->ifa_addr)->sin6_addr, buf, sizeof buf);
        for (auto &ip : ips)
            if (ip == buf) local = true;
    }
    freeifaddrs(ifa);
    return local;
}

// perf.PSCounter's JSON, as /ps answers: the "cpu" numbers and each "mem"
// entry's "rss", which are all a report reads.
Samples parsePS(const std::string &body) {
    Samples s;
    auto c = body.find("\"cpu\":[");
    if (c != std::string::npos) {
        const char *p = body.c_str() + c + 7;
        while (*p && *p != ']') {
            char *end;
            double v = strtod(p, &end);
            if (end == p) break;
            s.cpu.push_back(v);
            p = end;
            if (*p == ',') p++;
        }
    }
    auto m = body.find("\"mem\":[");
    if (m != std::string::npos) {
        auto stop = body.find(']', m);
        for (auto r = body.find("\"rss\":", m); r != std::string::npos && r < stop; r = body.find("\"rss\":", r + 6))
            s.rss.push_back(strtoull(body.c_str() + r + 6, nullptr, 10));
    }
    return s;
}

// config.PSSource: where the samples come from, and where the current phase
// starts - Mark - so that each phase's columns are its own.
struct PSSource {
    const Framework *fw;
    std::string ip;
    int64_t intervalNs;

    // Remote: the server's own samples, and how many it had at the mark.
    bool remote = true;
    size_t remoteCPUMark = 0, remoteMemMark = 0;

    // Local: this machine samples the server process on a thread.
    int pid = -1;
    std::mutex mu;
    Samples samples;
    size_t localMark = 0;
    int64_t markAt = 0;
    double markCPU = -1;
    bool fallback = false;  // also the server's own /ps, when it was asked to sample
    std::atomic<bool> stop{false};
    std::thread thread;

    ~PSSource() {
        stop = true;
        if (thread.joinable()) thread.join();
    }

    bool remotePS(Samples *out, std::string *err) {
        std::string body;
        if (!control(*fw, ip, "GET", "/ps", "", &body, err)) return false;
        *out = parsePS(body);
        return true;
    }

    bool startLocal(int p) {
        double cpu;
        uint64_t rss;
        if (!cpuSeconds(p, &cpu) || !rssBytes(p, &rss)) return false;
        pid = p;
        remote = false;
        markLocal();
        thread = std::thread([this, cpu]() mutable {
            double last = cpu;
            int64_t lastAt = nowNs();
            int errors = 0;
            while (!stop) {
                std::this_thread::sleep_for(std::chrono::nanoseconds(intervalNs));
                double now;
                uint64_t r;
                if (!cpuSeconds(pid, &now) || !rssBytes(pid, &r)) {
                    if (++errors >= 5) {
                        logf("sampling pid %d stopped after %d failures", pid, errors);
                        return;
                    }
                    continue;
                }
                errors = 0;
                int64_t at = nowNs();
                double percent = at > lastAt ? (now - last) / (double(at - lastAt) / 1e9) * 100 : 0;
                last = now, lastAt = at;
                std::lock_guard<std::mutex> g(mu);
                samples.cpu.push_back(percent);
                samples.rss.push_back(r);
            }
        });
        return true;
    }

    void markLocal() {
        double cpu = -1;
        if (!cpuSeconds(pid, &cpu)) cpu = -1;
        std::lock_guard<std::mutex> g(mu);
        localMark = samples.cpu.size();
        markAt = nowNs();
        markCPU = cpu;
    }

    // PSSource.Mark: a new phase, which leaves out every sample before it.
    void mark() {
        if (!remote) markLocal();
        if (remote || fallback) {
            Samples s;
            std::string err;
            if (remotePS(&s, &err)) remoteCPUMark = s.cpu.size(), remoteMemMark = s.rss.size();
        }
    }

    Samples remoteSince(std::string *err) {
        Samples s;
        if (!remotePS(&s, err)) return s;
        s.cpu.erase(s.cpu.begin(), s.cpu.begin() + std::min(remoteCPUMark, s.cpu.size()));
        s.rss.erase(s.rss.begin(), s.rss.begin() + std::min(remoteMemMark, s.rss.size()));
        if (s.cpu.empty())
            *err = std::string(fw->name) +
                   ": no CPU samples since this phase started, so it was shorter than the -pi sampling interval";
        return s;
    }

    // PSSource.PsInfo: the samples since the mark. A phase too short for two
    // samples - ten thousand handshakes can take less than one -pi interval -
    // gets the exact average from the process' CPU time since the mark.
    Samples info(std::string *err) {
        if (remote) return remoteSince(err);
        Samples s;
        int64_t at;
        double then;
        {
            std::lock_guard<std::mutex> g(mu);
            s.cpu.assign(samples.cpu.begin() + std::min(localMark, samples.cpu.size()), samples.cpu.end());
            s.rss.assign(samples.rss.begin() + std::min(localMark, samples.rss.size()), samples.rss.end());
            at = markAt, then = markCPU;
        }
        if (s.cpu.size() >= 2) return s;
        double now;
        uint64_t rss;
        double wall = double(nowNs() - at) / 1e9;
        if (then >= 0 && wall > 0 && cpuSeconds(pid, &now) && rssBytes(pid, &rss)) {
            Samples exact;
            exact.cpu = {(now - then) / wall * 100};
            exact.rss = s.rss.empty() ? std::vector<uint64_t>{rss} : s.rss;
            return exact;
        }
        if (!s.cpu.empty()) return s;
        if (fallback) return remoteSince(err);
        *err = "pid " + std::to_string(pid) + ": no CPU samples since this phase started";
        return s;
    }
};

// config.SetupPS: sample the server here when it runs on this machine, and
// have it sample itself, over /init and /ps, when it does not.
std::unique_ptr<PSSource> setupPS(const Framework &fw, const std::string &ip, const std::string &mode,
                                  int64_t intervalNs, int *serverPid) {
    auto src = std::make_unique<PSSource>();
    src->fw = &fw;
    src->ip = ip;
    src->intervalNs = intervalNs > 0 ? intervalNs : 1000000000;
    bool wantLocal = mode == "local" || (mode == "auto" && isLocalHost(ip));
    if (wantLocal) {
        std::string err;
        int pid = findServer(fw.name, &err);
        if (pid > 0 && src->startLocal(pid)) {
            logf("%s: sampled here, from pid %d, so it is not asked to sample itself", fw.name, pid);
            *serverPid = pid;
            return src;
        }
        if (pid > 0) err = "pid " + std::to_string(pid) + ": cannot read its CPU time";
        logf("%s: cannot sample the server from this machine, asking it over HTTP instead: %s", fw.name,
             err.c_str());
    }
    std::string body, err;
    char args[64];
    snprintf(args, sizeof args, "{\"PsInterval\":%lld}", (long long)src->intervalNs);
    if (!control(fw, ip, "POST", "/init", args, &body, &err)) {
        logf("SetupPS(%s) failed: %s", fw.name, err.c_str());
        return src;
    }
    *serverPid = atoi(body.c_str());
    return src;
}

// ---- TLS ----------------------------------------------------------------------

// What a handshake negotiated, in the names crypto/tls gives it, so that a
// report this client wrote reads like one benchcli-go wrote.
struct TLSParams {
    std::string version = "-", cipherSuite = "-", keyExchange = "-", certKey = "-";
};

TLSParams params(SSL *ssl) {
    TLSParams p;
    switch (SSL_version(ssl)) {
        case TLS1_1_VERSION: p.version = "TLS 1.1"; break;
        case TLS1_2_VERSION: p.version = "TLS 1.2"; break;
        case TLS1_3_VERSION: p.version = "TLS 1.3"; break;
        default: p.version = SSL_get_version(ssl);
    }
    if (auto *c = SSL_get_current_cipher(ssl)) p.cipherSuite = SSL_CIPHER_standard_name(c);
    // tls.CurveID.String: crypto/tls names the NIST curves CurveP256 and so on.
    if (auto *g = SSL_get_group_name(SSL_get_group_id(ssl))) {
        std::string name = g;
        p.keyExchange = name == "P-256" ? "CurveP256" : name == "P-384" ? "CurveP384" : name == "P-521" ? "CurveP521" : name;
    }
    // certs.KeyName: "ecdsa-p256", "rsa-2048", "ed25519".
    if (X509 *cert = SSL_get_peer_certificate(ssl)) {
        if (EVP_PKEY *key = X509_get_pubkey(cert)) {
            switch (EVP_PKEY_id(key)) {
                case EVP_PKEY_EC: p.certKey = "ecdsa-p" + std::to_string(EVP_PKEY_bits(key)); break;
                case EVP_PKEY_RSA: p.certKey = "rsa-" + std::to_string(EVP_PKEY_bits(key)); break;
                case EVP_PKEY_ED25519: p.certKey = "ed25519"; break;
            }
            EVP_PKEY_free(key);
        }
        X509_free(cert);
    }
    return p;
}

// The client's side of TLS, set up as benchcli-go's crypto/tls one is: the one
// version the framework is pinned to; the post-quantum X25519MLKEM768 first,
// then X25519, as crypto/tls offers them; no session cache, so that every
// handshake is a full one; and no check of the server's certificate chain -
// the benchmark measures the server's side of the handshake - while BoringSSL
// still verifies the handshake's signature with the certificate's key, as
// crypto/tls's InsecureSkipVerify does. BoringSSL's own cipher order already
// begins with AES-128-GCM, as crypto/tls's does.
SSL_CTX *clientContext(const char *version) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    uint16_t v = !strcmp(version, "1.1") ? TLS1_1_VERSION : !strcmp(version, "1.2") ? TLS1_2_VERSION : TLS1_3_VERSION;
    if (!ctx || !SSL_CTX_set_min_proto_version(ctx, v) || !SSL_CTX_set_max_proto_version(ctx, v) ||
        !SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519:P-256:P-384"))
        fatal("creating the TLS client context failed");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    return ctx;
}

// ---- The engine ---------------------------------------------------------------

enum Stage { Dial = 1, Warmup, Echo, Rate, Stop };

// A rate as golang.org/x/time/rate would give -el and -rl if it were set to
// what their usage says: that many a second, shared by every thread.
struct TokenBucket {
    std::mutex mu;
    double tokens = 0;
    int64_t limit = 0, last = 0;
    void reset(int64_t l) {
        std::lock_guard<std::mutex> g(mu);
        limit = l, tokens = double(l), last = nowNs();
    }
    bool take(int n) {
        if (!limit) return true;
        std::lock_guard<std::mutex> g(mu);
        auto now = nowNs();
        tokens = std::min(double(limit), tokens + double(now - last) * double(limit) / 1e9);
        last = now;
        if (tokens < n) return false;
        tokens -= n;
        return true;
    }
};

struct Shared {
    const Framework *fw;
    std::string host;
    std::atomic<int> stage{Dial};
    TokenBucket limiter;
    std::vector<std::string> payloads;  // 1024 random messages, as benchcli-go has
    std::string batch;                  // the Pipeline write: `pipeline` copies of payloads[0]
    int pipeline = 1, payload = 1024;
    bool check = false, tpn = true, nodelay = true;
    int64_t dialTimeout = 0, retryInterval = 0;
    int retries = 3;
    int64_t rateStart = 0, rateEnd = 0, rateInterval = 0;
    std::once_flag paramsOnce;
    TLSParams tls;
};

// benchpipeline.maxBatchesInFlight.
const int MAX_BATCHES_IN_FLIGHT = 4;
// How long an echo may take before its connection is given up on.
const int64_t IO_TIMEOUT = 30000000000LL;

struct Worker;
struct Conn {
    Worker *w;
    us_socket_t *s = nullptr;
    SSL *ssl = nullptr;
    BIO *rbio = nullptr, *wbio = nullptr;
    int id, attempt = 0, port = 0;
    uint64_t gen = 0;
    bool ready = false, completed = false, inflight = false;
    int64_t started = 0, echoStarted = 0;
    // The message in flight in Echo, and how much of its echo has arrived.
    int msg = 0;
    size_t got = 0;
    // Pipeline: messages sent and echoed, and how far into the message at the
    // front of the stream the bytes read so far have got.
    int64_t sent = 0, received = 0;
    size_t offset = 0;
    // Ciphertext the socket has not taken yet.
    std::string pending;
    std::list<Conn *>::iterator outstandingAt;
};

struct DialEvent {
    int64_t due;
    Conn *c;
    uint64_t gen;
    bool retry;
    bool operator<(const DialEvent &o) const { return due > o.due; }
};

struct Worker {
    Shared &sh;
    int id, count, dialConcurrency;
    int echoConcurrency = 0, rateConcurrency = 0;
    int64_t target = 0;
    std::atomic<int> done{0}, live{0};
    std::atomic<int64_t> rateSent{0}, rateRecv{0}, rateRecvBytes{0};
    Calc dialCalc, echoCalc;
    int64_t dialBegin = 0, dialEnd = 0, echoBegin = 0, echoEnd = 0;
    std::map<std::string, int> dialErrors;
    std::thread thread;
    us_loop_t *loop = nullptr;
    us_socket_context_t *ctx = nullptr;
    us_timer_t *timer = nullptr;
    SSL_CTX *sslctx = nullptr;
    int stage = Dial, next = 0, connecting = 0, completedCount = 0;
    int64_t issued = 0;
    bool stopping = false, filling = false;
    std::vector<std::unique_ptr<Conn>> conns;
    std::deque<Conn *> idle;
    std::list<Conn *> outstanding;
    std::priority_queue<DialEvent> dialEvents;
    std::vector<std::vector<Conn *>> teams;
    std::vector<int64_t> teamDue;
    std::mt19937_64 random{std::random_device{}()};
    std::vector<char> scratch = std::vector<char>(64 << 10);

    Worker(Shared &s, int i, int n, int dc) : sh(s), id(i), count(n), dialConcurrency(dc) {}

    static Conn &conn(us_socket_t *s) { return **static_cast<Conn **>(us_socket_ext(0, s)); }

    void start() { thread = std::thread([this] { run(); }); }
    void run();
    void tick();
    void beginStage(int s);
    void dial(Conn &c);
    void opened(Conn &c);
    void readable(Conn &c, char *data, int length);
    void plaintext(Conn &c, const char *data, size_t n);
    void handshakeDone(Conn &c);
    void send(Conn &c, const char *data, size_t n);
    void flushTLS(Conn &c);
    void flushSocket(Conn &c);
    void close(Conn &c);
    void lost(Conn &c);
    void attemptDone(Conn &c, bool ok);
    void fillEcho();
    void finishEcho(Conn &c, bool ok);
};

// Moves what BoringSSL sealed into the write BIO to the socket, keeping what
// the socket does not take behind whatever was already waiting.
void Worker::flushTLS(Conn &c) {
    const uint8_t *data;
    size_t len;
    if (!c.s || !BIO_mem_contents(c.wbio, &data, &len) || !len) return;
    if (!c.pending.empty()) c.pending.append((const char *)data, len);
    else {
        int n = us_socket_write(0, c.s, (const char *)data, int(len), 0);
        if (n < 0) n = 0;
        if (size_t(n) < len) c.pending.assign((const char *)data + n, len - size_t(n));
    }
    BIO_reset(c.wbio);
}

void Worker::flushSocket(Conn &c) {
    if (!c.s || c.pending.empty()) return;
    int n = us_socket_write(0, c.s, c.pending.data(), int(c.pending.size()), 0);
    if (n > 0) c.pending.erase(0, size_t(n));
}

void Worker::send(Conn &c, const char *data, size_t n) {
    if (!c.s) return;
    if (SSL_write(c.ssl, data, int(n)) != int(n)) {
        close(c);
        return;
    }
    flushTLS(c);
}

void Worker::close(Conn &c) {
    if (!c.s) return;
    if (us_socket_is_established(0, c.s)) us_socket_close(0, c.s, 0, nullptr);
    else {
        us_socket_close_connecting(0, c.s);
        lost(c);
    }
}

void Worker::attemptDone(Conn &c, bool ok) {
    c.completed = true;
    ++completedCount;
    --connecting;
    if (ok) dialCalc.costs.push_back(nowNs() - c.started);
    else ++dialCalc.failed;
}

void Worker::lost(Conn &c) {
    if (c.ssl) SSL_free(c.ssl);  // frees both BIOs
    c.ssl = nullptr, c.rbio = c.wbio = nullptr;
    c.s = nullptr;
    c.pending.clear();
    ++c.gen;
    if (c.ready) c.ready = false, --live;
    if (stopping) return;
    if (!c.completed) {
        if (c.attempt < sh.retries) dialEvents.push({nowNs() + sh.retryInterval, &c, c.gen, true});
        else attemptDone(c, false);
    } else if (c.inflight) finishEcho(c, false);
}

void Worker::dial(Conn &c) {
    ++c.attempt;
    ++c.gen;
    int ports = sh.fw->last - sh.fw->first + 1;
    c.port = sh.fw->first + int((int64_t(c.id) + c.attempt) % ports);
    c.s = us_socket_context_connect(0, ctx, sh.host.c_str(), c.port, nullptr, 0, sizeof(Conn *));
    if (!c.s) {
        lost(c);
        return;
    }
    *static_cast<Conn **>(us_socket_ext(0, c.s)) = &c;
    dialEvents.push({nowNs() + sh.dialTimeout, &c, c.gen, false});
}

// TCP is up: start the handshake.
void Worker::opened(Conn &c) {
    int fd = int(intptr_t(us_socket_get_native_handle(0, c.s)));
    int nodelay = sh.nodelay;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof nodelay);
    c.ssl = SSL_new(sslctx);
    c.rbio = BIO_new(BIO_s_mem());
    c.wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(c.ssl, c.rbio, c.wbio);
    SSL_set_connect_state(c.ssl);
    SSL_set_tlsext_host_name(c.ssl, SERVER_NAME);
    SSL_do_handshake(c.ssl);
    flushTLS(c);
}

void Worker::handshakeDone(Conn &c) {
    std::call_once(sh.paramsOnce, [&] { sh.tls = params(c.ssl); });
    c.ready = true;
    ++live;
    ++c.gen;  // the dial timeout no longer applies
    attemptDone(c, true);
}

// Ciphertext from the socket: into BoringSSL, and the plaintext out.
void Worker::readable(Conn &c, char *data, int length) {
    if (!c.ssl) return;
    BIO_write(c.rbio, data, length);
    if (!c.ready) {
        int r = SSL_do_handshake(c.ssl);
        flushTLS(c);
        if (r != 1) {
            int e = SSL_get_error(c.ssl, r);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                ERR_clear_error();
                close(c);
            }
            return;
        }
        handshakeDone(c);
    }
    for (;;) {
        int n = SSL_read(c.ssl, scratch.data(), int(scratch.size()));
        if (n > 0) {
            plaintext(c, scratch.data(), size_t(n));
            if (!c.s) return;
            continue;
        }
        int e = SSL_get_error(c.ssl, n);
        if (e == SSL_ERROR_WANT_READ) break;
        ERR_clear_error();
        close(c);
        return;
    }
    // Anything the reads made BoringSSL answer with, such as a key update.
    flushTLS(c);
}

void Worker::plaintext(Conn &c, const char *data, size_t n) {
    if (stage == Warmup || stage == Echo) {
        if (!c.inflight) {
            close(c);
            return;
        }
        auto &msg = sh.payloads[size_t(c.msg)];
        if (c.got + n > msg.size() || (sh.check && memcmp(data, msg.data() + c.got, n))) {
            finishEcho(c, false);
            close(c);
            return;
        }
        c.got += n;
        if (c.got == msg.size()) finishEcho(c, true);
    } else if (stage == Rate) {
        auto &msg = sh.payloads[0];
        if (sh.check) {
            // protocol.MatchesRepeated: the messages back to back, from wherever
            // the last piece left off.
            size_t off = c.offset, i = 0;
            while (i < n) {
                size_t k = std::min(n - i, msg.size() - off);
                if (memcmp(data + i, msg.data() + off, k)) {
                    logf("BenchPipeline: a connection echoed bytes that were not sent, leaving it out");
                    close(c);
                    return;
                }
                i += k, off = (off + k) % msg.size();
            }
        }
        c.offset += n;
        size_t msgs = c.offset / msg.size();
        if (msgs) {
            c.offset -= msgs * msg.size();
            c.received += int64_t(msgs);
            rateRecv.fetch_add(int64_t(msgs), std::memory_order_relaxed);
            rateRecvBytes.fetch_add(int64_t(msgs * msg.size()), std::memory_order_relaxed);
        }
    }
}

void Worker::finishEcho(Conn &c, bool ok) {
    if (!c.inflight) return;
    c.inflight = false;
    outstanding.erase(c.outstandingAt);
    if (ok) {
        if (stage == Echo) echoCalc.costs.push_back(nowNs() - c.echoStarted);
    } else ++echoCalc.failed;
    if (c.ready) idle.push_back(&c);
    fillEcho();
}

// One message in flight per connection, and at most echoConcurrency of them in
// flight on this thread, until the thread's share of the round trips is done.
void Worker::fillEcho() {
    if (filling || done.load() == stage || (stage != Warmup && stage != Echo)) return;
    filling = true;
    while (issued < target && outstanding.size() < size_t(echoConcurrency) && !idle.empty()) {
        Conn *c = idle.front();
        if (!c->ready) {
            idle.pop_front();
            continue;
        }
        if (!sh.limiter.take(1)) break;
        idle.pop_front();
        ++issued;
        c->msg = int(random() % sh.payloads.size());
        c->got = 0;
        c->echoStarted = nowNs();
        c->inflight = true;
        outstanding.push_back(c);
        c->outstandingAt = std::prev(outstanding.end());
        auto &msg = sh.payloads[size_t(c->msg)];
        send(*c, msg.data(), msg.size());
    }
    if (live.load() == 0 || echoConcurrency == 0) {
        echoCalc.failed += target - issued;
        issued = target;
    }
    if (issued == target && outstanding.empty()) {
        echoEnd = nowNs();
        done.store(stage, std::memory_order_release);
    }
    filling = false;
}

void Worker::beginStage(int s) {
    stage = s;
    if (stage == Warmup || stage == Echo) {
        echoCalc = Calc{};
        echoBegin = nowNs();
        issued = 0;
        idle.clear();
        outstanding.clear();
        for (auto &c : conns)
            if (c->ready) idle.push_back(c.get());
        fillEcho();
    } else if (stage == Rate) {
        teams.clear();
        teamDue.clear();
        int n = std::min(rateConcurrency, live.load());
        teams.resize(size_t(std::max(0, n)));
        size_t i = 0;
        for (auto &c : conns)
            if (c->ready && n) {
                c->sent = c->received = 0;
                c->offset = 0;
                teams[i++ % size_t(n)].push_back(c.get());
            }
        // Every team writes on exactly the ticks the duration holds: the first
        // at the start, then one each interval, while it is before the end.
        teamDue.assign(teams.size(), sh.rateStart);
    }
}

void Worker::tick() {
    int desired = sh.stage.load(std::memory_order_acquire);
    if (desired == Stop) {
        stopping = true;
        for (auto &c : conns) close(*c);
        us_timer_close(timer);
        timer = nullptr;
        return;
    }
    if (stage != desired) beginStage(desired);
    auto now = nowNs();
    if (stage == Dial && done.load() != Dial) {
        if (!dialBegin) dialBegin = now;
        while (!dialEvents.empty() && dialEvents.top().due <= now) {
            auto e = dialEvents.top();
            dialEvents.pop();
            auto &c = *e.c;
            if (c.gen != e.gen || c.completed) continue;
            if (e.retry) dial(c);
            else {
                ++dialErrors["i/o timeout"];
                close(c);
            }
        }
        while (next < count && connecting < dialConcurrency) {
            auto &c = *conns[size_t(next++)];
            ++connecting;
            c.started = nowNs();
            dial(c);
        }
        if (completedCount == count) {
            dialEvents = {};
            dialEnd = nowNs();
            done.store(Dial, std::memory_order_release);
        }
    } else if (stage == Warmup || stage == Echo) {
        while (!outstanding.empty() && now - outstanding.front()->echoStarted >= IO_TIMEOUT) close(*outstanding.front());
        fillEcho();
    } else if (stage == Rate && done.load() != Rate) {
        for (size_t t = 0; t < teams.size(); t++) {
            if (teamDue[t] > now || teamDue[t] >= sh.rateEnd) continue;
            for (Conn *c : teams[t]) {
                if (!c->ready || c->sent - c->received >= int64_t(sh.pipeline) * MAX_BATCHES_IN_FLIGHT) continue;
                if (!sh.limiter.take(sh.pipeline)) continue;
                send(*c, sh.batch.data(), sh.batch.size());
                if (c->ready) {
                    c->sent += sh.pipeline;
                    rateSent.fetch_add(sh.pipeline, std::memory_order_relaxed);
                }
            }
            // A team that has fallen behind skips the ticks it missed, as a
            // Go ticker drops them.
            teamDue[t] += sh.rateInterval;
            if (teamDue[t] <= now) teamDue[t] += ((now - teamDue[t]) / sh.rateInterval + 1) * sh.rateInterval;
        }
        if (now >= sh.rateEnd) done.store(Rate, std::memory_order_release);
    }
}

void noopLoop(us_loop_t *) {}

void Worker::run() {
    conns.reserve(size_t(count));
    for (int i = 0; i < count; i++) {
        conns.push_back(std::make_unique<Conn>());
        conns.back()->w = this;
        conns.back()->id = id * 1000003 + i;
    }
    sslctx = clientContext(sh.fw->version);
    loop = us_create_loop(nullptr, noopLoop, noopLoop, noopLoop, 0);
    us_socket_context_options_t none{};
    ctx = us_create_socket_context(0, loop, 0, none);
    if (!loop || !ctx) fatal("cannot allocate a uSockets loop");
    us_socket_context_on_open(0, ctx, [](us_socket_t *s, int, char *, int) {
        auto &c = conn(s);
        c.w->opened(c);
        return s;
    });
    us_socket_context_on_data(0, ctx, [](us_socket_t *s, char *data, int length) {
        auto &c = conn(s);
        c.w->readable(c, data, length);
        return s;
    });
    us_socket_context_on_writable(0, ctx, [](us_socket_t *s) {
        auto &c = conn(s);
        c.w->flushSocket(c);
        return s;
    });
    us_socket_context_on_close(0, ctx, [](us_socket_t *s, int, void *) {
        auto &c = conn(s);
        c.w->lost(c);
        return s;
    });
    us_socket_context_on_connect_error(0, ctx, [](us_socket_t *s, int code) {
        auto &c = conn(s);
        ++c.w->dialErrors[std::string("connect: ") + strerror(code ? code : ECONNREFUSED)];
        c.w->lost(c);
        return s;
    });
    us_socket_context_on_end(0, ctx, [](us_socket_t *s) {
        auto &c = conn(s);
        c.w->close(c);
        return s;
    });
    us_socket_context_on_timeout(0, ctx, [](us_socket_t *s) { return s; });
    timer = us_create_timer(loop, 0, sizeof(Worker *));
    *static_cast<Worker **>(us_timer_ext(timer)) = this;
    us_timer_set(timer, [](us_timer_t *t) { (*static_cast<Worker **>(us_timer_ext(t)))->tick(); }, 1, 1);
    us_loop_run(loop);
    us_socket_context_free(0, ctx);
    us_loop_free(loop);
    SSL_CTX_free(sslctx);
}

int availableCPUs() {
#ifdef __linux__
    cpu_set_t set;
    if (!sched_getaffinity(0, sizeof set, &set)) return std::max(1, CPU_COUNT(&set));
#endif
    return std::max(1, int(std::thread::hardware_concurrency()));
}

// ---- Reports ------------------------------------------------------------------

const char *BENCH_CLIENT = "benchcli-usockets";

std::string jsonString(const std::string &s) {
    std::string out = "\"";
    for (char ch : s) {
        if (ch == '"' || ch == '\\') out += '\\';
        out += ch;
    }
    return out + "\"";
}

// One report's fields, in the order the Go structs declare them, under their
// JSON names; config's TestUSocketsClientWritesEveryField holds the names to
// the Go ones.
struct JSON {
    std::string body;
    JSON &add(const char *k, const std::string &v) { return raw(k, jsonString(v)); }
    JSON &add(const char *k, int64_t v) { return raw(k, std::to_string(v)); }
    JSON &add(const char *k, uint64_t v) { return raw(k, std::to_string(v)); }
    JSON &add(const char *k, double v) {
        char b[64];
        snprintf(b, sizeof b, "%.17g", std::isfinite(v) ? v : 0.0);
        return raw(k, b);
    }
    JSON &add(const char *k, bool v) { return raw(k, v ? "true" : "false"); }
    JSON &raw(const char *k, const std::string &v) {
        body += (body.empty() ? "{" : ",") + jsonString(k) + ":" + v;
        return *this;
    }
    std::string str() const { return body + "}"; }
};

void writeFile(const std::string &path, const std::string &data) {
    FILE *f = fopen(path.c_str(), "wb");
    if (!f) {
        logf("writing %s failed: %s", path.c_str(), strerror(errno));
        return;
    }
    fwrite(data.data(), 1, data.size(), f);
    fclose(f);
}

// report.ToFile: the JSON, and the pprof profiles when there are any.
void toFile(const Flags &f, const std::string &name, const JSON &j, const std::string *cpu = nullptr,
            const std::string *mem = nullptr) {
    std::string base = "./output/report/" + f.str("preffix") + name + f.str("suffix");
    if (cpu && !cpu->empty()) writeFile(base + ".pprof.cpu", *cpu);
    if (mem && !mem->empty()) writeFile(base + ".pprof.mem", *mem);
    writeFile(base + ".json", j.str());
}

// report.ObjString: the block each benchmark prints as it finishes.
void console(const char *kind, const std::vector<std::pair<std::string, std::string>> &rows) {
    size_t width = strlen("BenchType");
    for (auto &r : rows) width = std::max(width, r.first.size());
    std::string out = std::string("BenchType") + std::string(width - 9, ' ') + ": " + kind + "\n";
    for (size_t i = 0; i < rows.size(); i++)
        out += rows[i].first + std::string(width - rows[i].first.size(), ' ') + ": " + rows[i].second +
               (i + 1 < rows.size() ? "\n" : "");
    std::lock_guard<std::mutex> g(logMu);
    fprintf(stderr, "%s%s\n\n%s", SHORT_LINE, out.c_str(), SHORT_LINE);
}

std::string pct(double v) {
    char b[64];
    snprintf(b, sizeof b, "%.2f%%", v);
    return b;
}
std::string f2(double v) {
    char b[64];
    snprintf(b, sizeof b, "%.2f", v);
    return b;
}

void addTLS(JSON &j, const TLSParams &t) {
    j.add("TLSVersion", t.version).add("CipherSuite", t.cipherSuite).add("KeyExchange", t.keyExchange).add("CertKey", t.certKey);
}
void addResources(JSON &j, const Resources &r) {
    j.add("CPUMin", r.cpuMin).add("CPUAvg", r.cpuAvg).add("CPUMax", r.cpuMax);
    j.add("MEMMin", r.memMin).add("MEMAvg", r.memAvg).add("MEMMax", r.memMax);
}
void addLatency(JSON &j, const Calc &c, bool tpn) {
    j.add("Min", tpn ? c.min() : c.min()).add("Avg", c.avg()).add("Max", c.max());
    j.add("TP50", tpn ? c.tpn(50) : int64_t(0)).add("TP75", tpn ? c.tpn(75) : int64_t(0));
    j.add("TP90", tpn ? c.tpn(90) : int64_t(0)).add("TP95", tpn ? c.tpn(95) : int64_t(0));
    j.add("TP99", tpn ? c.tpn(99) : int64_t(0));
}

// ---- pprof ----------------------------------------------------------------------

// The Go client's pprof hooks: two seconds into the phase, a CPU profile of
// -epd/-rpd seconds and a heap profile, written next to the report when they
// arrived in time. Only the Go servers serve them.
struct Profile {
    std::thread t;
    std::string cpu, mem;
    void start(const Framework &fw, const std::string &ip, const char *name, int seconds) {
        t = std::thread([this, &fw, ip, name, seconds] {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            std::string err, c, m;
            int port = fw.last + 1;
            if (httpRequest(ip, port, "GET", "/debug/pprof/profile?seconds=" + std::to_string(seconds), "",
                            seconds + 30, &c, &err) != 200) {
                logf("%s: [pprof cpu] httpGet failed: %s", name, err.c_str());
                return;
            }
            if (httpRequest(ip, port, "GET", "/debug/pprof/heap", "", 30, &m, &err) != 200) {
                logf("%s: [pprof mem] httpGet failed: %s", name, err.c_str());
                return;
            }
            cpu = c, mem = m;
        });
    }
    void join() {
        if (t.joinable()) t.join();
    }
};

// ---- The run --------------------------------------------------------------------

volatile std::sig_atomic_t interrupted = 0;

struct Runner {
    Shared &sh;
    std::vector<std::unique_ptr<Worker>> workers;
    Runner(Shared &s, int conns, int dc) : sh(s) {
        int threads = std::max(1, std::min({availableCPUs(), conns, dc}));
        for (int i = 0; i < threads; i++)
            workers.push_back(std::make_unique<Worker>(s, i, conns / threads + (i < conns % threads),
                                                       dc / threads + (i < dc % threads)));
        logf("Client: benchcli-usockets, event-loop threads: %d", threads);
    }
    ~Runner() {
        sh.stage.store(Stop, std::memory_order_release);
        for (auto &w : workers)
            if (w->thread.joinable()) w->thread.join();
    }
    void wait(int stage) {
        int64_t logAt = nowNs() + 1000000000;
        for (int i = 1;;) {
            if (interrupted) fatal("interrupted");
            bool all = true;
            for (auto &w : workers)
                if (w->done.load(std::memory_order_acquire) != stage) all = false;
            if (all) return;
            if (stage == Dial && nowNs() >= logAt) {
                int alive = 0;
                for (auto &w : workers) alive += w->live.load();
                logf("%03d seconds passed, %d Connected ...", i++, alive);
                logAt += 1000000000;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    int live() const {
        int n = 0;
        for (auto &w : workers) n += w->live.load();
        return n;
    }
    // Spreads a concurrency over the threads by the connections each holds.
    int allocate(int requested, bool rate) {
        int total = live(), wanted = std::min(requested, total), left = wanted;
        for (auto &w : workers) (rate ? w->rateConcurrency : w->echoConcurrency) = 0;
        while (left) {
            bool progress = false;
            for (auto &w : workers) {
                auto &q = rate ? w->rateConcurrency : w->echoConcurrency;
                if (left && q < w->live.load()) ++q, --left, progress = true;
            }
            if (!progress) break;
        }
        return wanted - left;
    }
    void echo(int stage, int64_t total, int concurrency) {
        int64_t assigned = 0, quota = 0;
        for (auto &w : workers) {
            quota += w->echoConcurrency;
            int64_t end = concurrency ? total * quota / concurrency : 0;
            w->target = end - assigned;
            assigned = end;
        }
        sh.stage.store(stage, std::memory_order_release);
        wait(stage);
    }
};

int run(const Flags &f) {
    const Framework *fw = findFramework(f.str("f"));
    if (!fw) {
        std::string names;
        for (auto &x : FRAMEWORKS) names += std::string(names.empty() ? "" : " ") + x.name;
        fatal("-f=" + f.str("f") + ": unknown framework \"" + f.str("f") + "\", want one of [" + names + "]");
    }
    std::string ip = f.str("ip");
    std::string lang = fw->lang;
    bool tpn = f.boolean("tpn");

    Shared sh;
    sh.fw = fw;
    sh.host = bareHost(ip);
    sh.check = f.boolean("check");
    sh.tpn = tpn;
    sh.nodelay = f.boolean("nodelay");
    sh.dialTimeout = f.dur("dt") ? f.dur("dt") : 1000000000;
    sh.retryInterval = f.dur("dri") ? f.dur("dri") : 100000000;
    sh.retries = f.num("dr") ? int(f.num("dr")) : 3;
    sh.payload = f.num("b") ? int(f.num("b")) : 1024;
    std::mt19937_64 rnd(std::random_device{}());
    for (int i = 0; i < 1024; i++) {
        std::string m(size_t(sh.payload), '\0');
        for (auto &ch : m) ch = char(rnd());
        sh.payloads.push_back(std::move(m));
    }
    // protocol.BatchBuffers and PipelineBuffers: -rpl messages a write, or as
    // many as -rbs holds, at least one and at most -rr, lowered to divide -rr.
    int sendRate = std::max<int>(1, int(f.num("rr")));
    int rpl = int(f.num("rpl"));
    if (rpl < 0 || (rpl > 0 && sendRate % rpl))
        fatal("-rpl=" + std::to_string(rpl) + ": pipeline does not divide the send rate " + std::to_string(sendRate));
    int batch = rpl > 0 ? rpl : std::max(1, std::min(sendRate, int(f.num("rbs")) / sh.payload));
    while (batch > 1 && sendRate % batch) --batch;
    sh.pipeline = batch;
    for (int i = 0; i < batch; i++) sh.batch += sh.payloads[0];

    fprintf(stderr, "%s", LONG_LINE);
    logf("Benchmark [%s]: %lld connections, %d payload, %lld times", fw->name, (long long)f.num("c"), sh.payload,
         (long long)f.num("en"));
    fprintf(stderr, "%s", SHORT_LINE);

    // How the server's CPU and MEM are sampled, settled before the connections
    // are dialed so that the handshakes are sampled too; each benchmark then
    // marks where its own phase starts.
    int serverPid = -1;
    auto ps = setupPS(*fw, ip, f.str("ps"), int64_t(f.num("pi")) * 1000000, &serverPid);
    bool hasPprof = lang == "go";

    int conns = f.num("c") ? int(f.num("c")) : 1000;
    int dc = f.num("dc") ? int(f.num("dc")) : availableCPUs() * 1000;
    dc = std::min(dc, conns);
    Runner runner(sh, conns, dc);
    logf("Dial Connections: [%d]", conns);
    logf("Dial Concurrency: [%d]", dc);
    logf("Connections start ...");
    ps->mark();
    for (auto &w : runner.workers) w->start();
    runner.wait(Dial);

    Calc dial;
    int64_t begin = 0, end = 0;
    std::map<std::string, int> errors;
    for (auto &w : runner.workers) {
        dial.costs.insert(dial.costs.end(), w->dialCalc.costs.begin(), w->dialCalc.costs.end());
        dial.failed += w->dialCalc.failed;
        if (!begin || (w->dialBegin && w->dialBegin < begin)) begin = w->dialBegin;
        end = std::max(end, w->dialEnd);
        for (auto &e : w->dialErrors) errors[e.first] += e.second;
    }
    dial.used = std::max<int64_t>(1, end - begin);
    dial.finish();
    logf("Connections done: %lld Success, %lld Failed", (long long)dial.success, (long long)dial.failed);
    if (!errors.empty()) {
        std::string s;
        for (auto &e : errors) s += (s.empty() ? "" : ", ") + e.first + ": " + std::to_string(e.second);
        logf("Connections errors: {%s}", s.c_str());
    }
    auto &t = sh.tls;
    logf("TLS: %s, %s, %s, certificate %s", t.version.c_str(), t.cipherSuite.c_str(), t.keyExchange.c_str(),
         t.certKey.c_str());
    std::string err;
    auto res = resources(ps->info(&err));
    if (!err.empty())
        logf("Connections: resource statistics for %s incomplete, CPU EER and MEM EER will read 0: %s", fw->name,
             err.c_str());
    {
        JSON j;
        j.add("Framework", std::string(fw->name)).add("Lang", lang).add("BenchClient", std::string(BENCH_CLIENT));
        addTLS(j, t);
        j.add("TPS", dial.tps()).add("CPUEER", cpuEER(double(dial.tps()), res.cpuAvg)).add("MEMEER", memEER(double(dial.tps()), res.memAvg));
        addLatency(j, dial, tpn);
        j.add("Used", dial.used).add("Total", int64_t(conns)).add("Success", dial.success).add("Failed", dial.failed);
        j.add("Concurrency", int64_t(dc));
        addResources(j, res);
        toFile(f, std::string(fw->name) + "-Connections", j);
        console("Connections",
                {{"Framework", fw->name}, {"Lang", lang}, {"Client", "c-usockets"}, {"TPS", std::to_string(dial.tps())},
                 {"CPU EER", f2(cpuEER(double(dial.tps()), res.cpuAvg))}, {"MEM EER", f2(memEER(double(dial.tps()), res.memAvg))},
                 {"Min", timeString(dial.min())}, {"Avg", timeString(dial.avg())}, {"Max", timeString(dial.max())},
                 {"TP95", timeString(dial.tpn(95))}, {"TP99", timeString(dial.tpn(99))}, {"Used", timeString(dial.used)},
                 {"Total", std::to_string(conns)}, {"Success", std::to_string(dial.success)},
                 {"Failed", std::to_string(dial.failed)}, {"Concurrency", std::to_string(dc)},
                 {"CPU Avg", pct(res.cpuAvg)}, {"CPU Max", pct(res.cpuMax)}, {"MEM Avg", memString(res.memAvg)},
                 {"MEM Max", memString(res.memMax)}});
    }
    if (!dial.success) fatal(std::string("Connections: no connection to ") + fw->name + " at " + ip + " succeeded, so there is nothing to benchmark on");

    // BenchEcho: a warmup of five round trips per connection - two million at
    // most - and then -en of them, measured.
    int ec = f.num("ec") ? int(f.num("ec")) : availableCPUs() * 1000;
    int concurrency = runner.allocate(ec, false);
    if (!concurrency) fatal("BenchEcho: no connections to run on");
    sh.limiter.reset(f.num("el"));
    int64_t warmup = std::min<int64_t>(int64_t(runner.live()) * 5, 2000000);
    logf("BenchEcho Warmup for %lld times ...", (long long)warmup);
    Profile echoProfile;
    if (f.boolean("ep") && hasPprof) echoProfile.start(*fw, ip, "BenchEcho", std::max<int>(1, int(f.num("epd"))));
    runner.echo(Warmup, warmup, concurrency);
    logf("BenchEcho Warmup for %lld times done", (long long)warmup);
    int64_t total = f.num("en");
    logf("BenchEcho for %lld times ...", (long long)total);
    ps->mark();
    runner.echo(Echo, total, concurrency);
    logf("BenchEcho for %lld times done", (long long)total);
    Calc echo;
    begin = end = 0;
    for (auto &w : runner.workers) {
        echo.costs.insert(echo.costs.end(), w->echoCalc.costs.begin(), w->echoCalc.costs.end());
        echo.failed += w->echoCalc.failed;
        if (!begin || (w->echoBegin && w->echoBegin < begin)) begin = w->echoBegin;
        end = std::max(end, w->echoEnd);
    }
    echo.used = std::max<int64_t>(1, end - begin);
    echo.finish();
    err.clear();
    res = resources(ps->info(&err));
    if (!err.empty())
        logf("BenchEcho: resource statistics for %s incomplete, CPU EER and MEM EER will read 0: %s", fw->name, err.c_str());
    echoProfile.join();
    {
        JSON j;
        j.add("Framework", std::string(fw->name)).add("Lang", lang).add("BenchClient", std::string(BENCH_CLIENT));
        addTLS(j, t);
        j.add("TPS", echo.tps()).add("CPUEER", cpuEER(double(echo.tps()), res.cpuAvg)).add("MEMEER", memEER(double(echo.tps()), res.memAvg));
        addLatency(j, echo, tpn);
        j.add("Used", echo.used).add("Total", total).add("Success", echo.success).add("Failed", echo.failed);
        j.add("Conns", dial.success).add("Concurrency", int64_t(concurrency)).add("Payload", int64_t(sh.payload));
        j.add("Pprof", f.boolean("ep"));
        addResources(j, res);
        toFile(f, std::string(fw->name) + "-BenchEcho", j, &echoProfile.cpu, &echoProfile.mem);
        console("BenchEcho",
                {{"Framework", fw->name}, {"Lang", lang}, {"Client", "c-usockets"}, {"TPS", std::to_string(echo.tps())},
                 {"CPU EER", f2(cpuEER(double(echo.tps()), res.cpuAvg))}, {"MEM EER", f2(memEER(double(echo.tps()), res.memAvg))},
                 {"Min", timeString(echo.min())}, {"Avg", timeString(echo.avg())}, {"Max", timeString(echo.max())},
                 {"TP95", timeString(echo.tpn(95))}, {"TP99", timeString(echo.tpn(99))}, {"Used", timeString(echo.used)},
                 {"Total", std::to_string(total)}, {"Success", std::to_string(echo.success)},
                 {"Failed", std::to_string(echo.failed)}, {"Conns", std::to_string(dial.success)},
                 {"Concurrency", std::to_string(concurrency)}, {"Payload", std::to_string(sh.payload)},
                 {"CPU Avg", pct(res.cpuAvg)}, {"CPU Max", pct(res.cpuMax)}, {"MEM Avg", memString(res.memAvg)},
                 {"MEM Max", memString(res.memMax)}});
    }

    if (f.boolean("rate")) {
        int rc = f.num("rc") ? int(f.num("rc")) : 50000;
        int rateConcurrency = runner.allocate(rc, true);
        sh.limiter.reset(f.num("rl"));
        int64_t seconds = f.num("rd") ? f.num("rd") : 10;
        int64_t duration = seconds * 1000000000;
        sh.rateInterval = std::max<int64_t>(1, 1000000000LL * sh.pipeline / sendRate);
        logf("BenchPipeline for %.2f seconds, %d messages per write ...", double(seconds), sh.pipeline);
        Profile rateProfile;
        if (f.boolean("rp") && hasPprof) rateProfile.start(*fw, ip, "BenchPipeline", std::max<int>(1, int(f.num("rpd"))));
        ps->mark();
        sh.rateStart = nowNs() + 1000000;
        sh.rateEnd = sh.rateStart + duration;
        sh.stage.store(Rate, std::memory_order_release);
        runner.wait(Rate);
        // One tick more for the last batch to come back, and no longer.
        auto sums = [&](int64_t *sent, int64_t *recv, int64_t *bytes) {
            *sent = *recv = *bytes = 0;
            for (auto &w : runner.workers)
                *sent += w->rateSent.load(), *recv += w->rateRecv.load(), *bytes += w->rateRecvBytes.load();
        };
        int64_t sent, recv, bytes, grace = nowNs() + sh.rateInterval;
        for (sums(&sent, &recv, &bytes); recv < sent && nowNs() < grace; sums(&sent, &recv, &bytes))
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        logf("BenchPipeline for %.2f seconds done", double(seconds));
        err.clear();
        res = resources(ps->info(&err));
        if (!err.empty())
            logf("BenchPipeline: resource statistics for %s incomplete, CPU EER and MEM EER will read 0: %s", fw->name,
                 err.c_str());
        rateProfile.join();
        double tps = double(recv) / double(seconds);
        JSON j;
        j.add("Framework", std::string(fw->name)).add("Lang", lang).add("BenchClient", std::string(BENCH_CLIENT));
        addTLS(j, t);
        j.add("Duration", duration).add("TPS", int64_t(std::floor(tps))).add("CPUEER", cpuEER(tps, res.cpuAvg)).add("MEMEER", memEER(tps, res.memAvg));
        j.add("SendTimes", sent).add("SendBytes", sent * sh.payload).add("RecvTimes", recv).add("RecvBytes", bytes);
        j.add("Conns", dial.success).add("Concurrency", int64_t(rateConcurrency)).add("SendRate", int64_t(sendRate));
        j.add("Pipeline", int64_t(sh.pipeline)).add("Payload", int64_t(sh.payload)).add("Pprof", f.boolean("rp"));
        addResources(j, res);
        toFile(f, std::string(fw->name) + "-BenchPipeline", j, &rateProfile.cpu, &rateProfile.mem);
        console("BenchPipeline",
                {{"Framework", fw->name}, {"Lang", lang}, {"Client", "c-usockets"}, {"Duration", timeString(duration)},
                 {"TPS", std::to_string(int64_t(tps))}, {"CPU EER", f2(cpuEER(tps, res.cpuAvg))},
                 {"MEM EER", f2(memEER(tps, res.memAvg))}, {"Msg Sent", std::to_string(sent)},
                 {"Bytes Sent", memString(uint64_t(sent * sh.payload))}, {"Msg Recv", std::to_string(recv)},
                 {"Bytes Recv", memString(uint64_t(bytes))}, {"Conns", std::to_string(dial.success)},
                 {"Concurrency", std::to_string(rateConcurrency)}, {"SendRate", std::to_string(sendRate)},
                 {"Pipeline", std::to_string(sh.pipeline)}, {"Payload", std::to_string(sh.payload)},
                 {"CPU Avg", pct(res.cpuAvg)}, {"CPU Max", pct(res.cpuMax)}, {"MEM Avg", memString(res.memAvg)},
                 {"MEM Max", memString(res.memMax)}});
    }
    fprintf(stderr, "%s", LONG_LINE);
    return 0;
}

}  // namespace

int main(int argc, char **argv) {
    std::signal(SIGINT, [](int) { interrupted = 1; });
    std::signal(SIGTERM, [](int) { interrupted = 1; });
    std::signal(SIGPIPE, SIG_IGN);
    char wd[4096];
    logf("pwd: %s", getcwd(wd, sizeof wd) ? wd : "");
    Flags f(argc, argv);
    if (f.str("sort") != "result" && f.str("sort") != "framework")
        fatal("report: unknown sort order \"" + f.str("sort") + "\", want one of [result framework]");
    if (f.str("ps") != "auto" && f.str("ps") != "local" && f.str("ps") != "remote")
        fatal("unsupported -ps value \"" + f.str("ps") + "\" (want auto, local or remote)");
    if (f.boolean("r"))
        fatal("-r: benchcli-usockets writes the JSON reports and leaves the tables to the Go client; run script/report.sh, or output/bin/bench.report -r=true");
    return run(f);
}
