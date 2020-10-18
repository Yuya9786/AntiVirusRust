use yara::*;
use std::env;
use walkdir::WalkDir;
use getopts::Options;

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("d", "dir", "scan under the directory", "DIR");
    opts.optopt("f", "file", "scan the file", "NAME");
    opts.optopt("r", "rule", "set the rules", "RULE");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    let rules = matches.opt_str("r");
    let file = matches.opt_str("f");
    let dir = matches.opt_str("d");

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    prescan(rules, file, dir);
    
}

fn prescan(rules: Option<String>, file:  Option<String>, dir: Option<String>) {
    if rules.is_none() {
        return;
    }
    let rules = rules.unwrap();

    if file.is_some() {
        file_scan(&rules, &(file.unwrap()));
        return;
    }

    if dir.is_some() {
        dir_scan(&rules, &(dir.unwrap()));
        return;
    }
}

fn file_scan(rules: &str, file: &str) {
    let mut compiler = Compiler::new().unwrap();
    compiler.add_rules_file(rules).unwrap();
    let rules = compiler.compile_rules().unwrap();

    let results = rules.scan_file(file, 5).unwrap();
    if results.len() != 0 {
        println!("{} may be a UPX file", file)
        // println!("{:?}", results);
    }
}

fn dir_scan(rules: &str, dir: &str) {
    let mut compiler = Compiler::new().unwrap();
    compiler.add_rules_file(rules).unwrap();
    let rules = compiler.compile_rules().unwrap();


    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        // let entry = entry.unwrap();
        let path = entry.path();
        // println!("{}", path.display());
        let file_type = entry.file_type();
        if file_type.is_file() {
            let results = rules.scan_file(path, 5).unwrap();
            if results.len() != 0 {
                println!("{} may be a UPX file", path.display())
                // println!("{:?}", results);
            }
        }
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}