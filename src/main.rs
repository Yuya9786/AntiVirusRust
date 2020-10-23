use walkdir::WalkDir;
use getopts::Options;
use std::{
    env,
    time::Instant,
    path::*,
};
use actix::prelude::*;
use actix::sync::SyncArbiter;
use futures::future::join_all;

mod scanner;
use scanner::{Scanner, Scan};

struct Server {
    // SyncArbiterに渡す構造体．AddrはSendとSyncが実装されているからスレッドに渡せる
    scanner: Addr<Scanner>,
}

impl Server {
    pub fn new(rules: PathBuf) -> Self {
        let scanner = SyncArbiter::start(4, move || Scanner::new(&rules));
        Self {
            scanner
        }
    }
}

#[actix_rt::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("t", "target", "scan the file or directory", "TARGET");
    opts.optopt("r", "rule", "set the rules", "RULE");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts).await;
        return;
    }
    let rules = matches.opt_str("r").expect("ERROR: rules not found.");
    let target = matches.opt_str("t").expect("ERROR: target not found.");

    let rules = PathBuf::from(&rules);
    let server = Server::new(rules);

    let scan_data = dir_scan(server, &target).await;

    println!("");
    println!("----------- SCAN SUMMARY -----------");
    println!("Time: {}.{:03} sec", scan_data.time_secs, scan_data.time_subsec_nanos);
    println!("May be infected:");
    for file in scan_data.infected {
        println!("{}", file.display());
    }
}

async fn dir_scan(server: Server, dir: &str) -> ScanData {
    let time_start = Instant::now();
    let mut results = vec![];
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()) {
        let file = entry.path().into();
        let timeout: u16 = 60;
        results.push(server.scanner.send(Scan { file, timeout }));
    }

    let mut infected = vec![];
    for scan_result in join_all(results).await {
        let scan_result = scan_result.unwrap();
        if scan_result.result.unwrap().len() > 0 {
            infected.push(scan_result.file);
        }
    }
    let end = time_start.elapsed();
    ScanData {
        time_secs: end.as_secs(),
        time_subsec_nanos: end.subsec_nanos() / 1_000_000,
        infected: infected,
    }
}

pub struct ScanData {
    pub time_secs: u64,
    pub time_subsec_nanos: u32,
    pub infected: Vec<PathBuf>,
}

async fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}