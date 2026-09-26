//! The rustls TLS echo server: rustls on tokio, through tokio-rustls, a task
//! per connection on tokio's multi-threaded runtime - which is how a Rust
//! program serves TLS without a framework, as frameworks/stdtls is how a Go
//! one does.
//!
//! It takes the Go servers' flags and serves what they serve: the variant -f
//! names, pinned to its TLS version, on its fifty benchmark ports, with a
//! certificate of the -key type issued at startup, and the control routes the
//! clients read its pid, CPU and memory from on the port after them.

mod control;
mod proc;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::NoServerSessionStorage;
use rustls::{CipherSuite, ServerConfig, SupportedProtocolVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// This server's variants in config.Variants: name, TLS version, first and
/// last benchmark port. config's TestRustTablesMatch holds this to the Go
/// table.
pub const VARIANTS: &[(&str, &str, u16, u16)] = &[
    ("rustls-tls12", "1.2", 12301, 12350),
    ("rustls-tls13", "1.3", 12401, 12450),
];

/// config.ServerName: what the certificate is issued to.
const SERVER_NAME: &str = "go-tls-benchmark";

/// fib/tls's DefaultHandshakeTimeout, which stdtls's server uses too.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

struct Flags {
    framework: String,
    nodelay: bool,
    reuseport: bool,
    payload: usize,
    key: String,
}

fn usage(err: &str) -> ! {
    if !err.is_empty() {
        eprintln!("{err}");
    }
    eprintln!("Usage of rustls.server:");
    eprintln!(
        "  -f value\n    \tframework: the variant to run, rustls-tls12 or rustls-tls13 (default \"rustls-tls13\")"
    );
    eprintln!("  -nodelay\n    \ttcp nodelay (default true)");
    eprintln!("  -reuseport\n    \treuse port (default true)");
    eprintln!(
        "  -b value\n    \texpected message size, which sizes the read buffers (default 1024)"
    );
    eprintln!("  -m value\n    \tmemory limit, ignored: there is no GC to limit");
    eprintln!(
        "  -key value\n    \tcertificate key: ecdsa (P-256), rsa (2048) or ed25519 (default \"ecdsa\")"
    );
    std::process::exit(2);
}

/// The Go servers' flags, in Go's flag syntax: -name=value or -name value, and
/// a bool flag on its own for true. One they do not define stops the server,
/// as it stops a Go one.
fn parse_flags() -> Flags {
    let mut f = Flags {
        framework: "rustls-tls13".into(),
        nodelay: true,
        reuseport: true,
        payload: 1024,
        key: "ecdsa".into(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let Some(flag) = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) else {
            break;
        };
        let (name, inline) = match flag.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (flag.to_string(), None),
        };
        let boolean = |v: Option<String>| match v.as_deref() {
            None | Some("1" | "t" | "T" | "true" | "TRUE" | "True") => true,
            Some("0" | "f" | "F" | "false" | "FALSE" | "False") => false,
            Some(v) => usage(&format!("invalid boolean value {v:?} for -{name}")),
        };
        let mut value = |v: Option<String>| {
            v.or_else(|| args.next())
                .unwrap_or_else(|| usage(&format!("flag needs an argument: -{name}")))
        };
        match name.as_str() {
            "h" | "help" => usage(""),
            "nodelay" => f.nodelay = boolean(inline),
            "reuseport" => f.reuseport = boolean(inline),
            "f" => f.framework = value(inline),
            "key" => f.key = value(inline),
            "m" => {
                value(inline);
            }
            "b" => {
                let v = value(inline);
                f.payload = v
                    .parse()
                    .unwrap_or_else(|_| usage(&format!("invalid value {v:?} for flag -b")));
            }
            _ => usage(&format!("flag provided but not defined: -{name}")),
        }
    }
    f
}

/// aws-lc-rs's provider with AES-128-GCM first, as crypto/tls orders it on a
/// machine with AES instructions, rather than AES-256-GCM, as rustls does. A
/// server picks from the client's order, and every client offers them in this
/// one, so that every pair of client and server negotiates the same suite.
pub fn provider() -> CryptoProvider {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    let rank = |s: CipherSuite| match s {
        CipherSuite::TLS13_AES_128_GCM_SHA256 => 0,
        CipherSuite::TLS13_AES_256_GCM_SHA384 => 1,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 2,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 3,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 4,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 5,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 6,
        _ => 7,
    };
    p.cipher_suites.sort_by_key(|s| rank(s.suite()));
    p
}

/// A self-signed certificate for SERVER_NAME with a new key of the -key type,
/// as package certs issues the Go servers theirs.
fn self_signed(key: &str) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), String> {
    let pair = match key {
        "ecdsa" => rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
        "rsa" => {
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
        }
        "ed25519" => rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519),
        _ => {
            return Err(format!(
                "unsupported certificate key {key:?}, want ecdsa, rsa or ed25519"
            ));
        }
    }
    .map_err(|e| format!("generating a {key} key: {e}"))?;
    let mut params =
        rcgen::CertificateParams::new(vec![SERVER_NAME.to_string(), "localhost".to_string()])
            .map_err(|e| e.to_string())?;
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress([127, 0, 0, 1].into()));
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, SERVER_NAME);
    let cert = params
        .self_signed(&pair)
        .map_err(|e| format!("issuing the certificate: {e}"))?;
    Ok((
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pair.serialize_der())),
    ))
}

/// What every Go server serves: the one version, the certificate, and
/// crypto/tls's session handling - one stateless ticket after a TLS 1.3
/// handshake, and tickets rather than a session cache for TLS 1.2.
fn server_config(
    version: &'static SupportedProtocolVersion,
    key: &str,
) -> Result<ServerConfig, String> {
    let (cert, key) = self_signed(key)?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[version])
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| e.to_string())?;
    config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().map_err(|e| e.to_string())?;
    config.send_tls13_tickets = 1;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    Ok(config)
}

fn main() {
    let flags = parse_flags();
    let Some(&(name, version, first, last)) = VARIANTS.iter().find(|v| v.0 == flags.framework)
    else {
        let names: Vec<&str> = VARIANTS.iter().map(|v| v.0).collect();
        eprintln!(
            "-f={}: not a variant of rustls, want one of {names:?}",
            flags.framework
        );
        std::process::exit(1);
    };
    let tls_version = match version {
        "1.2" => &rustls::version::TLS12,
        _ => &rustls::version::TLS13,
    };
    let config = server_config(tls_version, &flags.key).unwrap_or_else(|err| {
        eprintln!("{name}: {err}");
        std::process::exit(1)
    });
    let acceptor = TlsAcceptor::from(Arc::new(config));

    // available_parallelism reads the affinity mask script/env.sh pins the
    // server with, and a cgroup quota, as GOMAXPROCS does on the Go side.
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    eprintln!(
        "{name} server: nodelay={}, reuseport={}, payload={}, tls={version}, key={}, worker threads={cpus}",
        flags.nodelay, flags.reuseport, flags.payload, flags.key
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cpus)
        .enable_all()
        .build()
        .expect("building the tokio runtime");
    runtime.block_on(async move {
        for port in first..=last {
            let listener = listen(port, flags.reuseport).unwrap_or_else(|err| {
                eprintln!("{name}: listen on port {port} failed: {err}");
                std::process::exit(1)
            });
            tokio::spawn(accept_loop(
                listener,
                acceptor.clone(),
                flags.nodelay,
                flags.payload.max(1),
            ));
        }
        let control = listen(last + 1, flags.reuseport).unwrap_or_else(|err| {
            eprintln!("{name}: listen on control port {} failed: {err}", last + 1);
            std::process::exit(1)
        });
        tokio::spawn(control::serve(control));
        eprintln!(
            "{name} server: listening on {} ports, :{first} to :{last}",
            last - first + 1
        );
        wait_signal().await;
        eprintln!("{name} server: exit");
    });
}

/// SIGINT, which script/killone.sh sends, or SIGTERM.
async fn wait_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = int.recv() => {}
        _ = term.recv() => {}
    }
}

/// A listener on every interface, with SO_REUSEPORT unless -reuseport=false,
/// and the backlog the Go servers listen with.
fn listen(port: u16, reuseport: bool) -> io::Result<TcpListener> {
    use socket2::{Domain, Socket, Type};
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.set_reuse_address(true)?;
    if reuseport {
        socket.set_reuse_port(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(65535)?;
    TcpListener::from_std(socket.into())
}

async fn accept_loop(listener: TcpListener, acceptor: TlsAcceptor, nodelay: bool, payload: usize) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let _ = stream.set_nodelay(nodelay);
                tokio::spawn(echo(stream, acceptor.clone(), payload));
            }
            Err(err) => {
                // Out of file descriptors, most likely. Back off rather than
                // spin on it; the connections already accepted keep being
                // served meanwhile.
                eprintln!("accept failed: {err}");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

/// The handshake, then whatever the connection reads written back, until it
/// closes. The buffer is the connection's own for as long as it is open, as
/// stdtls's is: rustls hands back at most what the buffer holds of the
/// plaintext it has decrypted and keeps the rest for the next read.
async fn echo(stream: TcpStream, acceptor: TlsAcceptor, payload: usize) {
    let Ok(Ok(mut tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
    else {
        return;
    };
    let mut buf = vec![0u8; payload];
    loop {
        let n = match tls.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        // write_all hands rustls the plaintext, which it seals into records;
        // flush writes out whatever of them the socket did not take at once.
        if tls.write_all(&buf[..n]).await.is_err() || tls.flush().await.is_err() {
            return;
        }
    }
}
