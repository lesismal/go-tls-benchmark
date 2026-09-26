//! The three benchmarks, as benchcli-go runs them: Connections dials the TLS
//! connections, each a full handshake, BenchEcho makes round trips on them,
//! and BenchPipeline pipelines messages on them at a set rate.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::config;
use crate::logf;
use crate::protocol::{batch_buffers, matches_repeated, pipeline_buffers};
use crate::stats::Calc;
use crate::tls::{self, Params};

/// One TLS connection to the server. A round trip that failed leaves the
/// stream at an unknown point, so a broken connection carries nothing more
/// until it is redialed.
pub struct Conn {
    stream: TlsStream<TcpStream>,
    addr: String,
    broken: bool,
}

/// What every dial needs: the TLS configuration, how long a connect and its
/// handshake may take, and what the first handshake negotiated.
pub struct Dialer {
    connector: TlsConnector,
    timeout: Duration,
    nodelay: bool,
    params: OnceLock<Params>,
}

impl Dialer {
    pub fn new(config: ClientConfig, timeout: Duration, nodelay: bool) -> Self {
        Dialer {
            connector: TlsConnector::from(Arc::new(config)),
            timeout,
            nodelay,
            params: OnceLock::new(),
        }
    }

    /// What the first handshake negotiated, or dashes before there was one.
    pub fn params(&self) -> Params {
        self.params.get().cloned().unwrap_or_default()
    }

    /// connections.dial: a TCP connection and a full TLS handshake on it.
    async fn dial(&self, addr: &str) -> io::Result<TlsStream<TcpStream>> {
        let fut = async {
            let tcp = TcpStream::connect(addr).await?;
            tcp.set_nodelay(self.nodelay)?;
            let stream = self.connector.connect(tls::server_name(), tcp).await?;
            self.params.get_or_init(|| tls::params(stream.get_ref().1));
            Ok(stream)
        };
        tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "i/o timeout"))?
    }

    async fn redial(&self, c: &mut Conn) -> io::Result<()> {
        c.stream = self.dial(&c.addr).await?;
        c.broken = false;
        Ok(())
    }
}

fn default_concurrency() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get()) * 1000
}

pub struct ConnectionsResult {
    pub calc: Calc,
    pub concurrency: usize,
    pub conns: Vec<Conn>,
}

/// connections.Run.
pub async fn connections(
    framework: &str,
    ip: &str,
    num: usize,
    concurrency: usize,
    retries: usize,
    retry_interval: Duration,
    dialer: Arc<Dialer>,
) -> ConnectionsResult {
    let num = if num == 0 { 1000 } else { num };
    let concurrency = if concurrency == 0 {
        default_concurrency()
    } else {
        concurrency
    }
    .min(num);
    let retries = if retries == 0 { 3 } else { retries };
    let retry_interval = if retry_interval.is_zero() {
        Duration::from_millis(100)
    } else {
        retry_interval
    };
    logf!("Dial Connections: [{num}]");
    logf!("Dial Concurrency: [{concurrency}]");

    let addrs = Arc::new(config::benchmark_addrs(framework, ip));
    let next = Arc::new(AtomicUsize::new(0));
    let server_idx = Arc::new(AtomicUsize::new(0));
    let success = Arc::new(AtomicI64::new(0));
    let conns = Arc::new(std::sync::Mutex::new(Vec::with_capacity(num)));

    let progress = {
        let success = Arc::clone(&success);
        tokio::spawn(async move {
            let mut i = 0;
            loop {
                i += 1;
                tokio::time::sleep(Duration::from_secs(1)).await;
                logf!(
                    "{i:03} seconds passed, {} Connected ...",
                    success.load(Ordering::Relaxed)
                );
            }
        })
    };

    logf!("Connections start ...");
    let begin = Instant::now();
    let mut tasks = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let (addrs, next, server_idx, success, conns, dialer) = (
            Arc::clone(&addrs),
            Arc::clone(&next),
            Arc::clone(&server_idx),
            Arc::clone(&success),
            Arc::clone(&conns),
            Arc::clone(&dialer),
        );
        tasks.push(tokio::spawn(async move {
            let (mut costs, mut failed) = (Vec::new(), 0i64);
            let mut errors = HashMap::<String, usize>::new();
            while next.fetch_add(1, Ordering::Relaxed) < num {
                let t = Instant::now();
                let mut dialed = None;
                for attempt in 0..retries {
                    if attempt > 0 {
                        tokio::time::sleep(retry_interval).await;
                    }
                    let addr =
                        &addrs[(server_idx.fetch_add(1, Ordering::Relaxed) + 1) % addrs.len()];
                    match dialer.dial(addr).await {
                        Ok(stream) => {
                            dialed = Some(Conn {
                                stream,
                                addr: addr.clone(),
                                broken: false,
                            });
                            break;
                        }
                        Err(err) if attempt + 1 == retries => {
                            *errors.entry(err.to_string()).or_default() += 1;
                        }
                        Err(_) => {}
                    }
                }
                match dialed {
                    Some(c) => {
                        costs.push(t.elapsed().as_nanos() as i64);
                        success.fetch_add(1, Ordering::Relaxed);
                        conns.lock().unwrap().push(c);
                    }
                    None => failed += 1,
                }
            }
            (costs, failed, errors)
        }));
    }
    let (mut costs, mut failed) = (Vec::with_capacity(num), 0);
    let mut errors = HashMap::<String, usize>::new();
    for t in tasks {
        let (c, f, e) = t.await.expect("dial task");
        costs.extend(c);
        failed += f;
        for (k, v) in e {
            *errors.entry(k).or_default() += v;
        }
    }
    let used = begin.elapsed();
    progress.abort();
    let calc = Calc::new(used, costs, failed);
    logf!(
        "Connections done: {} Success, {} Failed",
        calc.success,
        calc.failed
    );
    if !errors.is_empty() {
        logf!("Connections errors: {errors:?}");
    }
    let conns = std::mem::take(&mut *conns.lock().unwrap());
    ConnectionsResult {
        calc,
        concurrency,
        conns,
    }
}

/// A rate as golang.org/x/time/rate would give -el and -rl if it were set
/// to what their usage says: that many a second, spaced evenly.
struct Limiter {
    per_second: usize,
    next: Mutex<Instant>,
}

impl Limiter {
    fn new(per_second: usize) -> Option<Arc<Self>> {
        (per_second > 0).then(|| {
            Arc::new(Limiter {
                per_second,
                next: Mutex::new(Instant::now()),
            })
        })
    }

    async fn wait(&self, n: usize) {
        let at = {
            let mut next = self.next.lock().await;
            let at = (*next).max(Instant::now());
            *next = at + Duration::from_secs_f64(n as f64 / self.per_second as f64);
            at
        };
        tokio::time::sleep_until(at.into()).await;
    }
}

/// A small, fast, per-task generator for the random payloads and for which
/// of them the next message is.
struct XorShift(u64);

impl XorShift {
    fn seeded(salt: u64) -> Self {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        XorShift((t ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15)) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

fn random_payload(payload: usize, salt: u64) -> Vec<u8> {
    let mut buf = vec![0; payload];
    XorShift::seeded(salt).fill(&mut buf);
    buf
}

pub struct EchoConfig {
    pub concurrency: usize,
    pub total: usize,
    pub payload: usize,
    pub limit: usize,
    pub check: bool,
}

pub struct EchoResult {
    pub calc: Calc,
    pub concurrency: usize,
    pub conns: Vec<Conn>,
}

struct EchoShared {
    payloads: Vec<Vec<u8>>,
    next: AtomicUsize,
    total: usize,
    check: bool,
    limiter: Option<Arc<Limiter>>,
    dialer: Arc<Dialer>,
}

/// benchecho.Run: a warmup of five round trips per connection - two million
/// at most - and then cfg.total of them, measured, each connection carrying
/// one message at a time. Every task has connections of its own, so no
/// connection is ever wanted by two tasks at once. on_benchmark runs when the
/// warmup is over, which is where the resource columns' phase starts.
pub async fn echo<F: std::future::Future<Output = ()>>(
    conns: Vec<Conn>,
    cfg: EchoConfig,
    dialer: Arc<Dialer>,
    on_warmup: impl FnOnce(),
    on_benchmark: impl FnOnce() -> F,
) -> EchoResult {
    let concurrency = if cfg.concurrency == 0 {
        default_concurrency()
    } else {
        cfg.concurrency
    }
    .min(conns.len());
    if concurrency == 0 {
        crate::fatalf!("BenchEcho: no connections to run on");
    }
    let payload = if cfg.payload == 0 { 1024 } else { cfg.payload };
    let payloads = (0..1024).map(|i| random_payload(payload, i)).collect();
    let warmup = (conns.len() * 5).min(2_000_000);
    let mut shared = EchoShared {
        payloads,
        next: AtomicUsize::new(0),
        total: warmup,
        check: cfg.check,
        limiter: Limiter::new(cfg.limit),
        dialer,
    };

    let mut groups: Vec<Vec<Conn>> = (0..concurrency).map(|_| Vec::new()).collect();
    for (i, c) in conns.into_iter().enumerate() {
        groups[i % concurrency].push(c);
    }

    logf!("BenchEcho Warmup for {warmup} times ...");
    on_warmup();
    let (g, _, _, _) = echo_phase(groups, shared).await;
    groups = g.0;
    shared = g.1;
    logf!("BenchEcho Warmup for {warmup} times done");

    shared.next.store(0, Ordering::SeqCst);
    shared.total = cfg.total;
    logf!("BenchEcho for {} times ...", cfg.total);
    on_benchmark().await;
    let begin = Instant::now();
    let ((groups, _), costs, failed, errors) = echo_phase(groups, shared).await;
    let used = begin.elapsed();
    logf!("BenchEcho for {} times done", cfg.total);
    if !errors.is_empty() {
        logf!("BenchEcho errors: {errors:?}");
    }
    EchoResult {
        calc: Calc::new(used, costs, failed),
        concurrency,
        conns: groups.into_iter().flatten().collect(),
    }
}

type Groups = (Vec<Vec<Conn>>, EchoShared);

async fn echo_phase(
    groups: Vec<Vec<Conn>>,
    shared: EchoShared,
) -> (Groups, Vec<i64>, i64, HashMap<String, usize>) {
    let shared = Arc::new(shared);
    let mut tasks = Vec::with_capacity(groups.len());
    for (i, mut group) in groups.into_iter().enumerate() {
        let shared = Arc::clone(&shared);
        tasks.push(tokio::spawn(async move {
            let mut rng = XorShift::seeded(i as u64 + 1);
            let (mut costs, mut failed, mut errors) =
                (Vec::new(), 0i64, HashMap::<String, usize>::new());
            let mut rbuf = Vec::new();
            let mut at = 0;
            while shared.next.fetch_add(1, Ordering::Relaxed) < shared.total {
                let this = at;
                at = (at + 1) % group.len();
                let c = &mut group[this];
                let t = Instant::now();
                match echo_once(c, &shared, &mut rng, &mut rbuf).await {
                    Ok(()) => costs.push(t.elapsed().as_nanos() as i64),
                    Err(err) => {
                        failed += 1;
                        *errors.entry(err).or_default() += 1;
                    }
                }
            }
            (group, costs, failed, errors)
        }));
    }
    let (mut groups, mut costs, mut failed, mut errors) =
        (Vec::new(), Vec::new(), 0, HashMap::new());
    for t in tasks {
        let (g, c, f, e) = t.await.expect("echo task");
        groups.push(g);
        costs.extend(c);
        failed += f;
        for (k, v) in e {
            *errors.entry(k).or_default() += v;
        }
    }
    let shared = Arc::try_unwrap(shared).ok().expect("echo tasks done");
    ((groups, shared), costs, failed, errors)
}

/// One message written, sealed into one record, and the same number of bytes
/// read back, in however many records the server answered in.
async fn echo_once(
    c: &mut Conn,
    s: &EchoShared,
    rng: &mut XorShift,
    rbuf: &mut Vec<u8>,
) -> Result<(), String> {
    if c.broken {
        s.dialer
            .redial(c)
            .await
            .map_err(|err| format!("redial: {err}"))?;
    }
    if let Some(l) = &s.limiter {
        l.wait(1).await;
    }
    let payload = &s.payloads[(rng.next() % s.payloads.len() as u64) as usize];
    if let Err(err) = async {
        c.stream.write_all(payload).await?;
        c.stream.flush().await
    }
    .await
    {
        c.broken = true;
        return Err(err.to_string());
    }
    rbuf.resize(payload.len(), 0);
    if let Err(err) = c.stream.read_exact(rbuf).await {
        c.broken = true;
        return Err(err.to_string());
    }
    if s.check && rbuf.as_slice() != payload.as_slice() {
        c.broken = true;
        return Err("echo is not equal to the message sent".into());
    }
    Ok(())
}

pub struct PipelineConfig {
    pub concurrency: usize,
    pub duration: Duration,
    pub send_rate: usize,
    pub batch_size: usize,
    pub pipeline: usize,
    pub payload: usize,
    pub send_limit: usize,
    pub check: bool,
}

#[derive(Default)]
pub struct PipelineResult {
    pub concurrency: usize,
    pub batch: usize,
    pub send_times: i64,
    pub send_bytes: i64,
    pub recv_times: i64,
    pub recv_bytes: i64,
}

#[derive(Default)]
struct Counters {
    send_times: AtomicI64,
    send_bytes: AtomicI64,
    recv_times: AtomicI64,
    recv_bytes: AtomicI64,
}

/// benchpipeline.maxBatchesInFlight.
const MAX_BATCHES_IN_FLIGHT: i64 = 4;

/// benchpipeline.Run: every connection is sent cfg.send_rate messages a
/// second, written a batch at a time without waiting for the echoes of the
/// ones before, and a task per connection reads the echoes back. A connection
/// with more than a few batches unanswered is skipped for a tick.
pub async fn pipeline<F: std::future::Future<Output = ()>>(
    conns: Vec<Conn>,
    cfg: PipelineConfig,
    dialer: Arc<Dialer>,
    on_benchmark: impl FnOnce() -> F,
) -> PipelineResult {
    let concurrency = if cfg.concurrency == 0 {
        50000
    } else {
        cfg.concurrency
    }
    .min(conns.len());
    if concurrency == 0 {
        crate::fatalf!("BenchPipeline: no connections to run on");
    }
    let send_rate = cfg.send_rate.max(1);
    let payload = if cfg.payload == 0 { 1024 } else { cfg.payload };
    let msg = Arc::new(random_payload(payload, 0xB0D1));
    let (batch_buffer, batch, tick_rate) = if cfg.pipeline > 0 {
        pipeline_buffers(&msg, send_rate, cfg.pipeline)
    } else {
        batch_buffers(&msg, send_rate, cfg.batch_size)
    };
    if tick_rate == 0 || batch_buffer.is_empty() {
        crate::fatalf!(
            "BenchPipeline got a wrong tickRate: {tick_rate}, or batchBuffer: {}",
            batch_buffer.len()
        );
    }
    let batch_buffer = Arc::new(batch_buffer);
    let limiter = Limiter::new(cfg.send_limit);
    let counters = Arc::new(Counters::default());

    let mut writers = Vec::new();
    let mut readers = Vec::new();
    for mut c in conns {
        if c.broken {
            if let Err(err) = dialer.redial(&mut c).await {
                logf!(
                    "BenchPipeline: redial {} failed, leaving the connection out: {err}",
                    c.addr
                );
                continue;
            }
        }
        let addr = c.addr.clone();
        let (tcp, tls) = c.stream.into_inner();
        let pc = Arc::new(PipeConn {
            tcp,
            tls: std::sync::Mutex::new(tls),
        });
        let inflight = Arc::new((AtomicI64::new(0), AtomicI64::new(0)));
        let (counters, msg, check, flight, reader) = (
            Arc::clone(&counters),
            Arc::clone(&msg),
            cfg.check,
            Arc::clone(&inflight),
            Arc::clone(&pc),
        );
        readers.push(tokio::spawn(async move {
            // How far into the message at the front of the stream the bytes
            // read so far have got.
            let mut offset = 0usize;
            loop {
                if reader.tcp.readable().await.is_err() {
                    return;
                }
                let got = match reader.read_plaintext(|plain| {
                    if check && !matches_repeated(plain, &msg, offset) {
                        return false;
                    }
                    offset += plain.len();
                    true
                }) {
                    Ok(Some(true)) => true,
                    Ok(Some(false)) => {
                        logf!("BenchPipeline: {addr} echoed bytes that were not sent, leaving the connection out");
                        return;
                    }
                    Ok(None) => false,
                    Err(_) => return,
                };
                if !got {
                    continue;
                }
                let msgs = offset / payload;
                if msgs > 0 {
                    offset -= msgs * payload;
                    flight.1.fetch_add(msgs as i64, Ordering::Relaxed);
                    counters.recv_times.fetch_add(msgs as i64, Ordering::Relaxed);
                    counters
                        .recv_bytes
                        .fetch_add((msgs * payload) as i64, Ordering::Relaxed);
                }
            }
        }));
        writers.push((pc, inflight));
    }

    let mut teams: Vec<Vec<_>> = (0..concurrency).map(|_| Vec::new()).collect();
    for (i, w) in writers.into_iter().enumerate() {
        teams[i % concurrency].push(w);
    }

    logf!(
        "BenchPipeline for {:.2} seconds, {batch} messages per write ...",
        cfg.duration.as_secs_f64()
    );
    on_benchmark().await;
    // Every writer writes its batches on exactly the ticks the duration
    // holds, the last of them right at its end, as benchcli-go's do; the
    // deadline is only the backstop for a writer that has fallen behind, half
    // a tick after the last one was due.
    let period = Duration::from_secs(1) / tick_rate as u32;
    let ticks = (cfg.duration.as_nanos() / period.as_nanos()) as usize;
    let deadline = tokio::time::Instant::now() + cfg.duration + period / 2;
    let mut tasks = Vec::with_capacity(teams.len());
    for mut team in teams {
        let (batch_buffer, counters, limiter) = (
            Arc::clone(&batch_buffer),
            Arc::clone(&counters),
            limiter.clone(),
        );
        tasks.push(tokio::spawn(async move {
            // The records a batch is sealed into, reused for every write.
            let mut sealed = Vec::with_capacity(batch_buffer.len() + 1024);
            let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            for _ in 0..ticks {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => return team,
                    _ = ticker.tick() => {}
                }
                for (pc, flight) in team.iter_mut() {
                    if flight.0.load(Ordering::Relaxed) - flight.1.load(Ordering::Relaxed)
                        >= batch as i64 * MAX_BATCHES_IN_FLIGHT
                    {
                        continue;
                    }
                    if let Some(l) = &limiter {
                        l.wait(batch).await;
                    }
                    if pc.write(&batch_buffer, &mut sealed).await.is_ok() {
                        counters
                            .send_times
                            .fetch_add(batch as i64, Ordering::Relaxed);
                        counters
                            .send_bytes
                            .fetch_add((batch * payload) as i64, Ordering::Relaxed);
                        flight.0.fetch_add(batch as i64, Ordering::Relaxed);
                    }
                }
            }
            team
        }));
    }
    // The connections are kept, not dropped, until the last batch has had its
    // tick to come back: dropping them would close them.
    let mut write_halves = Vec::with_capacity(tasks.len());
    for t in tasks {
        if let Ok(team) = t.await {
            write_halves.push(team);
        }
    }

    // One tick more for the last batch to come back, and no longer.
    let grace = Instant::now() + period;
    while counters.recv_times.load(Ordering::Relaxed) < counters.send_times.load(Ordering::Relaxed)
        && Instant::now() < grace
    {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let result = PipelineResult {
        concurrency,
        batch,
        send_times: counters.send_times.load(Ordering::Relaxed),
        send_bytes: counters.send_bytes.load(Ordering::Relaxed),
        recv_times: counters.recv_times.load(Ordering::Relaxed),
        recv_bytes: counters.recv_bytes.load(Ordering::Relaxed),
    };
    for r in readers {
        r.abort();
    }
    drop(write_halves);
    logf!(
        "BenchPipeline for {:.2} seconds done",
        cfg.duration.as_secs_f64()
    );
    result
}

/// A connection as BenchPipeline drives it: rustls's connection state beside
/// the socket rather than wrapped around it, as tokio-rustls has it.
///
/// tokio-rustls reads the socket through rustls's read_tls, 4KiB a call, and
/// shrinks rustls's buffer back each time it empties, so a batch sealed into
/// one 16KiB record takes four reads and a reallocation to come back - what a
/// crypto/tls client does in one. Here each reader waits for the socket to be
/// readable without holding a buffer, reads all that has arrived into one per
/// thread, and hands that to rustls, which is the way rustls's own examples
/// drive a connection for throughput. Nothing is kept per connection but what
/// rustls keeps, so the phase costs a client no more memory at a million
/// connections than tokio-rustls does.
struct PipeConn {
    tcp: TcpStream,
    tls: std::sync::Mutex<rustls::ClientConnection>,
}

thread_local! {
    /// What one read takes off a socket: 64KiB, four full records.
    static CIPHERTEXT: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0; 64 << 10]);
    /// What rustls decrypts them into.
    static PLAINTEXT: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0; 16 << 10]);
}

impl PipeConn {
    /// Reads what the socket has, decrypts it, and hands the plaintext to f,
    /// piece by piece, until f says no. None when the readiness was spurious
    /// and there was nothing to read; Some(false) when f refused a piece.
    fn read_plaintext(&self, mut f: impl FnMut(&[u8]) -> bool) -> io::Result<Option<bool>> {
        CIPHERTEXT.with_borrow_mut(|cipher| {
            let n = match self.tcp.try_read(cipher) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => n,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(err) => return Err(err),
            };
            let mut tls = self.tls.lock().unwrap();
            let mut rest = &cipher[..n];
            PLAINTEXT.with_borrow_mut(|plain| {
                while !rest.is_empty() {
                    tls.read_tls(&mut rest)?;
                    tls.process_new_packets().map_err(io::Error::other)?;
                    loop {
                        match io::Read::read(&mut tls.reader(), plain) {
                            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                            Ok(m) => {
                                if !f(&plain[..m]) {
                                    return Ok(Some(false));
                                }
                            }
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                            Err(err) => return Err(err),
                        }
                    }
                }
                Ok(Some(true))
            })
        })
    }

    /// Seals data into records, into sealed, and writes them to the socket.
    async fn write(&self, data: &[u8], sealed: &mut Vec<u8>) -> io::Result<()> {
        sealed.clear();
        {
            let mut tls = self.tls.lock().unwrap();
            io::Write::write_all(&mut tls.writer(), data)?;
            while tls.wants_write() {
                tls.write_tls(sealed)?;
            }
        }
        let mut at = 0;
        while at < sealed.len() {
            self.tcp.writable().await?;
            match self.tcp.try_write(&sealed[at..]) {
                Ok(n) => at += n,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }
}
