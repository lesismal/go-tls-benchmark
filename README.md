# go-tls-benchmark

A benchmark of TLS servers, laid out like
[go-websocket-benchmark](https://github.com/lesismal/go-websocket-benchmark):
the same scripts, the same three phases, the same report tables. Every server
is a TLS echo server - it writes back the plaintext it reads - so what differs
between them is how they run TLS, not a protocol on top of it.

| Server | Lang | |
| --- | --- | --- |
| `fib` | go | [github.com/lesismal/fib](https://github.com/lesismal/fib): its event loop does the I/O, and [`fib/tls`](https://github.com/lesismal/fib/tree/main/tls) runs crypto/tls in front of an echo handler |
| `rustls` | rust | [rustls](https://github.com/rustls/rustls) on tokio, through tokio-rustls, with aws-lc-rs as its cryptography: a task per connection on tokio's multi-threaded runtime |
| `stdtls` | go | the standard library: `crypto/tls` over `net`, a goroutine per connection |
| `usockets` | c | [uSockets](https://github.com/uNetworking/uSockets) - the event loops and TLS under [uWebSockets](https://github.com/uNetworking/uWebSockets) and Bun - with [BoringSSL](https://boringssl.googlesource.com/boringssl): an event loop per CPU, each listening on every port with `SO_REUSEPORT`, echoing from the loop's read callback |

## Frameworks: a server per TLS version

What a run measures - a row of the tables - is a server pinned to one TLS
version, named `<server>-tls<version>`: both the server and the client offer
only that version, so the row measures the version it says it does.

| Framework | TLS | Benchmark ports | Control port |
| --- | --- | --- | --- |
| `fib-tls11` | 1.1 | 12001-12050 | 12051 |
| `fib-tls12` | 1.2 | 12101-12150 | 12151 |
| `fib-tls13` | 1.3 | 12201-12250 | 12251 |
| `rustls-tls12` | 1.2 | 12301-12350 | 12351 |
| `rustls-tls13` | 1.3 | 12401-12450 | 12451 |
| `stdtls-tls11` | 1.1 | 12501-12550 | 12551 |
| `stdtls-tls12` | 1.2 | 12601-12650 | 12651 |
| `stdtls-tls13` | 1.3 | 12701-12750 | 12751 |
| `usockets-tls11` | 1.1 | 12801-12850 | 12851 |
| `usockets-tls12` | 1.2 | 12901-12950 | 12951 |
| `usockets-tls13` | 1.3 | 13001-13050 | 13051 |

rustls implements TLS 1.2 and 1.3 only, so it has no `-tls11`; crypto/tls
and BoringSSL still speak 1.0 as well, which is left out as measuring nothing 1.1 does not
(the two were deprecated together, RFC 8996, and negotiate the same CBC cipher
suites). The list is `config.Variants` in [config/config.go](config/config.go);
a variant is one more row there, with the next free block of ports.

Each framework has ports of its own, so that on a server node of a two-node
run all of them are up at once. `script/build.sh` builds each server once, to
`output/bin/base/<server>`, and each framework as a hard link to it,
`output/bin/<framework>.server`, which is started with `-f=<framework>`: the
name is what the scripts stop it by and what the client finds it by to sample
its CPU and memory.

Pick what a run measures by framework, by server, and by version:

```sh
# Every TLS version of fib, and rustls-tls13
BENCH_FRAMEWORKS=fib,rustls-tls13 bash script/benchmark.sh

# TLS 1.3 only, every server
BENCH_TLS_VERSIONS=1.3 bash script/benchmark.sh
```

Every server issues itself a certificate at startup and uses its TLS
library's defaults for the rest, set to match crypto/tls's, so that every pair
of client and server negotiates the same handshake:

- the key exchange: the post-quantum hybrid `X25519MLKEM768` first for TLS
  1.3, whose key exchange costs more than plain `X25519`, and `X25519` for 1.2
  and 1.1. crypto/tls and rustls (on aws-lc-rs) offer it by default; the
  usockets server sets BoringSSL's groups to the same list. BoringSSL, rather
  than the system's OpenSSL, is also why usockets can: Debian's OpenSSL 3.0
  has no `X25519MLKEM768`.
- the cipher suite: every server takes the client's order, and every client
  offers AES-128-GCM first - rustls is told to, where its own default is
  AES-256-GCM - or, at TLS 1.1, AES-128-CBC-SHA.
- session tickets: one stateless ticket after a TLS 1.3 handshake and no
  server-side session cache, as crypto/tls has it, where rustls's default is
  two tickets backed by a cache and BoringSSL's two tickets.

## Clients

`script/config.sh` selects the client with `BENCH_CLIENT`:

| `BENCH_CLIENT` | Client | Summary's `Client` |
| --- | --- | --- |
| `benchcli-usockets` (default) | C++, on [uSockets](https://github.com/uNetworking/uSockets) event loops - one per CPU, each owning its share of the connections - and BoringSSL; builds from the sources the usockets server builds from | `c-usockets` |
| `benchcli-rustls` | Rust, rustls on tokio (tokio-rustls, aws-lc-rs); needs cargo 1.85+ | `rust-rustls` |
| `benchcli-go` | Go, crypto/tls, a goroutine per connection | `go-crypto/tls` |

```sh
BENCH_CLIENT=benchcli-go bash script/benchmark.sh
```

All three take the same flags, run the same three phases the same way and
write the same JSON report files, which the report step - the Go client
whichever measured - turns into the tables. rustls does not implement TLS
1.1, so under `benchcli-rustls` the `*-tls11` frameworks are measured by
`benchcli-go` (`script/client.sh` picks it), and the Summary's `Client` row
says which client measured which rows; the other two measure every framework.

None of them keeps a session cache, so every handshake is a full one, and none
verifies the server's certificate chain - the benchmark measures the servers'
side of the handshake, and a client checking a chain on the machine it shares
with the server would only take CPU from it - while all three still verify
the handshake's signature with the certificate's key. They offer the same
handshake: the one TLS version the framework is pinned to, `X25519MLKEM768`
then `X25519`, AES-128-GCM first.

`benchcli-usockets` runs uSockets' sockets as plain TCP and drives BoringSSL
through memory BIOs itself, rather than through uSockets' own TLS layer: that
one starts a client's handshake only when the application first writes, and
says nothing when it completes, which is the moment Connections times.

### Why benchcli-usockets is the default

A client is only as good as how little it holds the server back. All three
were run against every TLS 1.2 and 1.3 framework (the ones all three can
speak), with the defaults (10,000 connections, 1KB messages), in the Docker
runner on an Apple M4 Pro. For each of the 24 rows - 8 frameworks, 3 phases -
the client that got the most out of the server is the best, and each client
is scored by its share of the best, averaged geometrically, and by how many
rows it is within 1% of the best on:

| | benchcli-go | benchcli-rustls | benchcli-usockets |
| --- | --- | --- | --- |
| Server 3 CPUs, client 4 (the runner's split): share of the best | 85% | 97% | 96% |
| rows within 1% of the best | 3 | 11 | 14 |
| Server 4 CPUs, client 2 (client-bound): share of the best | 75% | 88% | 94% |
| rows within 1% of the best | 6 | 10 | 10 |

Given fewer CPUs than the server, so that the client is the bottleneck and
what is measured is the client, benchcli-usockets is clearly ahead; with the
runner's own split it and benchcli-rustls are within a point of each other,
and benchcli-usockets is the best on more rows - it is the only one that takes
every framework's BenchPipeline to the 2,000,000 cap wherever the server can
reach it. benchcli-rustls completes the most handshakes when starved of CPUs
and the most echo round trips against the Go servers; benchcli-go generates
the most BenchPipeline traffic when starved, and holds the servers back most
everywhere else. That, and measuring TLS 1.1 without falling back to another
client, makes benchcli-usockets the default.

## What a run measures

Each client runs three phases against each framework in turn, on the same
connections:

| Phase | What it does | TPS is |
| --- | --- | --- |
| `Connections` | dials `-c` connections, `-dc` at a time, each a TCP connect and a **full** TLS handshake | full handshakes per second |
| `BenchEcho` | writes `-b` random bytes on a connection and reads the echo back, `-ec` connections at a time, `-en` times | round trips per second |
| `BenchPipeline` | writes `-rr` messages a second to every connection, as many to a write as fit in `-rbs` bytes, without waiting for echoes, for `-rd` seconds | echoes read back per second |

Every phase has the server's CPU and memory next to its TPS, and `CPU EER` and
`MEM EER` - TPS per percent of a core, and per MB of resident memory. A full
handshake is mostly CPU, the certificate key's signature above all, so
`Connections` is sampled like the other two, and each phase's columns are that
phase's alone: the sampler marks where each one starts. A phase shorter than
the sampling interval (`-pi`, 1s) - ten thousand handshakes can take less -
gets the exact average from the process' CPU time over the phase instead.

### Report layout

Every table - `Connections`, `BenchEcho`, `BenchPipeline` - is written as one
table per TLS version, newest first, each under a `#### TLS 1.x` heading and
ranked on its own: TLS 1.1 and 1.3 differ in round trips, cipher suites and
key exchange, so one table of both would rank the versions as much as the
servers. What the handshakes negotiated is in the Summary table in front of
them, a row per version:

```
| Cipher Suite (TLS 1.3) | TLS_AES_128_GCM_SHA256                  | Cipher suite the handshakes of that TLS version negotiated                           |
| Cipher Suite (TLS 1.2) | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | Cipher suite the handshakes of that TLS version negotiated                           |
| Cipher Suite (TLS 1.1) | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    | Cipher suite the handshakes of that TLS version negotiated                           |
| Key Exchange (TLS 1.3) | X25519MLKEM768                          | Key exchange the handshakes of that TLS version negotiated                           |
| Key Exchange (TLS 1.2) | X25519                                  | Key exchange the handshakes of that TLS version negotiated                           |
| Key Exchange (TLS 1.1) | X25519                                  | Key exchange the handshakes of that TLS version negotiated                           |
| Cert Key               | ecdsa-p256                              | The servers' certificate key (-key on the servers), which signs every full handshake |
```

These are read off a handshake rather than copied from the configuration, so
the report says what was measured; a row that lists more than one value, each
with the frameworks it came from, is a pair of client and server that did not
agree with the rest.

### The certificate key

`-key` goes to the servers only - the client reports the key it was served:
`ecdsa` (P-256, the default), `rsa` (2048) or `ed25519`. Full handshakes with
RSA cost the server several times what they do with ECDSA.

```sh
bash script/benchmark.sh -key=rsa
```

## Run

```sh
git clone https://github.com/lesismal/go-tls-benchmark.git
cd go-tls-benchmark
./script/benchmark.sh

# A subset, smaller
BENCH_FRAMEWORKS=fib-tls13,rustls-tls13 bash script/benchmark.sh -c=1000 -en=200000
```

It builds every server and the client into `output/bin`, runs each framework in
turn - started right before its client and stopped right after it, so no
other server holds CPU or memory while one is measured - and writes the
reports to `output/report`: one JSON file per framework and phase, and
`Summary.md`, `Connections.md`, `BenchEcho.md` and `BenchPipeline.md`. On
Linux the servers and the client are pinned to separate halves of the CPUs
with `taskset`. The flags the scripts take are the client's - see
`./output/bin/bench.client -h` - and the servers are handed the ones they
define.

`script/benchmarkN.sh` runs every framework through the matrix of connections
and payloads in `script/config.sh`, and `script/1m_conns_benchmark.sh` holds a
million connections (see the system settings below).

### Docker

The Docker runner reads the CPU set and memory exposed by the Docker daemon,
uses about 75% of its CPUs and 80% of its memory, pins separate CPU groups for
the servers and client, runs with `--network none`, and copies reports, logs,
console output and the resource plan to `output/docker/<timestamp>`. The image
has every toolchain - Go, Rust, and cmake and g++ for C and C++ - and fetches
and compiles the Rust crates, uSockets and BoringSSL when it is built, so both
clients and every server build in the container with no network.

```sh
# Short validation of rustls, stdtls and usockets, every TLS version
bash script/docker_benchmark.sh --smoke

# Full benchmark, with either client
bash script/docker_benchmark.sh
BENCH_CLIENT=benchcli-rustls bash script/docker_benchmark.sh

# Focused run with explicit resource limits
BENCH_FRAMEWORKS=fib,rustls BENCH_TLS_VERSIONS=1.3 \
DOCKER_BENCH_CPUS=8 DOCKER_BENCH_MEMORY=12g \
bash script/docker_benchmark.sh -c=10000 -en=2000000 -b=1024 -key=rsa
```

From mainland China, `script/docker_benchmark_cn.sh` takes the same options and
builds the image from mirrors (DaoCloud for Docker Hub, Aliyun for apt,
goproxy.cn for Go modules, rsproxy.cn for crates.io). Only the build downloads anything, so the results
are comparable with `script/docker_benchmark.sh`'s.

## Report row order

Each table - one per TLS version - is written best first, ranked by `TPS`, with `CPU EER` breaking a
tie and `MEM EER` a tie on both; `[↓1]`, `[↓2]` and `[↓3]` on the column titles
say which is which, and each of those columns shows every row's share of the
best in it. `-sort=framework` (`BENCH_REPORT_SORT=framework`) keeps
`config.FrameworkList`'s order instead, which puts a framework on the same row
in every table and across runs. The report step alone can re-read a finished
run the other way round:

```sh
bash script/report.sh -sort=framework
```

## Two nodes

A single-node run divides the machine's CPUs between the servers and the
client. To put each on its own machine:

```sh
# On the server node: builds the servers, starts them, leaves them running.
BENCH_ROLE=server bash script/benchmark.sh

# On the client node: builds the client, runs it against the servers, reports.
BENCH_ROLE=client BENCH_SERVER_HOST=10.0.0.2 bash script/benchmark.sh

# Back on the server node, when the run is over.
bash script/killall.sh
```

The client then reads the servers' CPU and memory from their own `/ps` route
on the control port (the one after each framework's fifty benchmark ports, in
plaintext), since it cannot see their processes; on one node it samples them
from the operating system. `-ps=auto|local|remote` overrides that.

## Before running the test

Make sure the system settings allow the connections, for example (on both
machines of a two-node run):

```sh
sysctl -w net.ipv4.ip_local_port_range="1024 65535"
# Keep the servers' ports (config.Ports) out of that range: each server starts
# just before its turn, and would fail to bind a port the client before it left
# in TIME_WAIT. The run prints the exact list when they are not reserved.
sysctl -w net.ipv4.ip_local_reserved_ports=12001-13051
sysctl -w fs.file-max=2000500
sysctl -w fs.nr_open=2000500
sysctl -w net.nf_conntrack_max=2000500
ulimit -n 2000500
sysctl -w net.core.somaxconn=2048
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.ipv4.tcp_tw_reuse=1
```
