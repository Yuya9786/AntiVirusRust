use yara::*;
use std::env;
use walkdir::WalkDir;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut compiler = Compiler::new().unwrap();
    compiler.add_rules_file(&args[1]).unwrap();
    let rules = compiler.compile_rules().unwrap();


    for entry in WalkDir::new("/usr/").into_iter().filter_map(|e| e.ok()) {
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
