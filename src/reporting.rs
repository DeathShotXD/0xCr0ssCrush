//! Uniform research-report output.
//!
//! Every observation the tool makes is emitted through `Report` so the
//! human-readable console and the `--json` machine output stay in sync.
//!
//! The schema is stable and documented in `docs/architecture.md` under
//! "Output contract".

use std::fmt;

pub enum Event {
    Info(String),
    Driver(String, String, String, String), // kind, device, ioctl, digest-prefix
    KillResolved(String, u32),
    KillSubmitted {
        pid: u32,
        ok: bool,
    },
    KillResult {
        pid: u32,
        result: &'static str,
        detail: String,
    },
    Rejected(String),
    Summary {
        submitted: usize,
        resolved: usize,
    },
}

pub struct Output {
    pub json: bool,
}

impl Output {
    pub fn new(json: bool) -> Self {
        Self { json }
    }

    pub fn emit(&self, e: Event, pid_note: Option<u32>) {
        match e {
            Event::Info(m) => self.line("info", &m, pid_note),
            Event::Driver(kind, dev, ioctl, digest) => self.driver(&kind, &dev, &ioctl, &digest),
            Event::KillResolved(name, pid) => {
                self.line("resolved", &format!("{name} -> pid {pid}"), None)
            }
            Event::KillSubmitted { pid, ok } => {
                if self.json {
                    self.line(
                        "submitted",
                        if ok {
                            "ioctl submitted"
                        } else {
                            "ioctl failed"
                        },
                        Some(pid),
                    );
                } else if ok {
                    println!("[+] submitted pid {pid}");
                }
            }
            Event::KillResult {
                pid,
                result,
                detail,
            } => {
                let m = format!("{result} {detail}");
                self.line("kill", &m, Some(pid));
            }
            Event::Rejected(m) => self.line("rejected", &m, None),
            Event::Summary {
                submitted,
                resolved,
            } => self.summary(submitted, resolved),
        }
    }

    fn driver(&self, kind: &str, dev: &str, ioctl: &str, digest: &str) {
        if self.json {
            println!(
                "{{\"event\":\"driver\",\"driver\":\"{kind}\",\"device\":\"{dev}\",\"ioctl\":\"{ioctl}\",\"sha256\":\"{digest}\"}}"
            );
        } else {
            println!("[*] driver {kind}");
            println!("    device   {dev}");
            println!("    ioctl    {ioctl}");
            println!("    sha256   {digest}");
        }
    }

    fn line(&self, event: &str, msg: &str, pid: Option<u32>) {
        if self.json {
            match pid {
                Some(p) => println!("{{\"event\":\"{event}\",\"pid\":{p},\"message\":\"{msg}\"}}"),
                None => println!("{{\"event\":\"{event}\",\"message\":\"{msg}\"}}"),
            }
        } else {
            match pid {
                Some(p) => println!("[{event}] pid {p}: {msg}"),
                None => println!("[{event}] {msg}"),
            }
        }
    }

    fn summary(&self, submitted: usize, resolved: usize) {
        if self.json {
            println!("{{\"event\":\"summary\",\"submitted\":{submitted},\"resolved\":{resolved}}}");
        } else {
            println!("[+] submitted {submitted} IOCTLs, {resolved} targets resolved");
        }
    }
}

impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "output(json={})", self.json)
    }
}
