//! The control routes the Go servers serve with frameworks.HandleCommon, on
//! the port after the benchmark ones, in plaintext: /init starts sampling the
//! process' CPU and memory and answers with its pid, and /ps answers with the
//! samples, in the shape github.com/lesismal/perf's PSCounter marshals to -
//! the "cpu" and "mem"[].rss fields, which are all the clients read. There is
//! no /debug/pprof: the clients ask only Go servers for profiles.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::proc;

pub async fn serve(listener: TcpListener) {
    loop {
        if let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(handle(stream));
        }
    }
}

/// One request per connection, answered with Connection: close.
async fn handle(mut stream: TcpStream) {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let (head_len, content_length) = loop {
        let n = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_string();
            let length = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.trim()
                        .eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            break (end + 4, length);
        }
        if buf.len() > 64 << 10 {
            return;
        }
    };
    while buf.len() < head_len + content_length {
        let n = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf[..head_len]).to_string();
    let mut request_line = head.lines().next().unwrap_or("").split_whitespace();
    let (method, path) = (
        request_line.next().unwrap_or(""),
        request_line.next().unwrap_or(""),
    );
    let path = path.split('?').next().unwrap_or(path);
    let body = &buf[head_len..head_len + content_length];
    let (status, content_type, reply) = match (method, path) {
        ("POST", "/init") => {
            SAMPLER.start(Duration::from_nanos(ps_interval_nanos(body)));
            (
                "200 OK",
                "text/plain; charset=utf-8",
                std::process::id().to_string(),
            )
        }
        ("GET", "/ps") => ("200 OK", "application/json", SAMPLER.json()),
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "404 page not found\n".to_string(),
        ),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// The body encoding/json makes of config.InitArgs, {"PsInterval":1000000000}.
fn ps_interval_nanos(body: &[u8]) -> u64 {
    let body = String::from_utf8_lossy(body);
    let Some(at) = body.find("PsInterval") else {
        return 0;
    };
    let rest = &body[at + "PsInterval".len()..];
    let rest = rest[rest.find(':').map_or(rest.len(), |i| i + 1)..].trim_start();
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

struct Sampler {
    started: AtomicBool,
    samples: Mutex<(Vec<f64>, Vec<u64>)>,
}

static SAMPLER: Sampler = Sampler {
    started: AtomicBool::new(false),
    samples: Mutex::new((Vec::new(), Vec::new())),
};

impl Sampler {
    /// Once, however many times /init arrives, as the Go servers guard theirs:
    /// a client that retried the request can deliver it twice.
    fn start(&'static self, interval: Duration) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let interval = if interval.is_zero() {
            Duration::from_secs(1)
        } else {
            interval
        };
        std::thread::spawn(move || {
            let pid = std::process::id() as i32;
            let mut last_cpu = proc::cpu_time(pid).unwrap_or_default();
            let mut last_at = Instant::now();
            loop {
                std::thread::sleep(interval);
                let now = Instant::now();
                let cpu = proc::cpu_time(pid).unwrap_or(last_cpu);
                let wall = now.duration_since(last_at).as_secs_f64();
                let percent = if wall > 0.0 {
                    cpu.saturating_sub(last_cpu).as_secs_f64() / wall * 100.0
                } else {
                    0.0
                };
                (last_cpu, last_at) = (cpu, now);
                let rss = proc::rss_bytes(pid).unwrap_or(0);
                let mut samples = self.samples.lock().unwrap();
                samples.0.push(percent);
                samples.1.push(rss);
            }
        });
    }

    fn json(&self) -> String {
        let samples = self.samples.lock().unwrap();
        let cpu: Vec<String> = samples.0.iter().map(|c| c.to_string()).collect();
        let mem: Vec<String> = samples
            .1
            .iter()
            .map(|r| format!("{{\"rss\":{r}}}"))
            .collect();
        format!(
            "{{\"cpu\":[{}],\"mem\":[{}]}}",
            cpu.join(","),
            mem.join(",")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_body() {
        assert_eq!(
            ps_interval_nanos(br#"{"PsInterval":1000000000}"#),
            1_000_000_000
        );
        assert_eq!(ps_interval_nanos(br#"{"PsInterval": 5}"#), 5);
        assert_eq!(ps_interval_nanos(b"{}"), 0);
    }
}
