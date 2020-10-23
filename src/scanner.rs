use actix::prelude::*;
use yara::*;
use std::path::PathBuf;
use actix::dev::*;

pub struct Scanner {
    rules: Rules
}

impl Scanner {
    pub fn new(rules: &PathBuf) -> Self {
        let mut compiler = Compiler::new().unwrap();
        compiler.add_rules_file(rules).unwrap();
        let rules = compiler.compile_rules().unwrap();
        Self { rules: rules }
    }
}

impl Actor for Scanner {
    type Context = SyncContext<Self>;
}

// スキャンメッセージ
#[derive(Debug, Message)]
#[rtype(result = "ScanResult")]
pub struct Scan {
    pub file: PathBuf,
    pub timeout: u16,
}

// スキャンメッセージを受け入れることができるアクターが返す必要のある値
#[derive(Debug)]
pub struct ScanResult {
    pub file: PathBuf,
    pub result: Result<Vec<String>, yara::Error>,
}

impl<A, M> MessageResponse<A, M> for ScanResult
where
    A: Actor,
    M: Message<Result = Self>,
{
    fn handle<R: ResponseChannel<M>>(self, _: &mut A::Context, tx: Option<R>) {
        if let Some(tx) = tx {
            tx.send(self);
        }
    }
}

impl Handler<Scan> for Scanner {
    type Result = ScanResult;

    fn handle(&mut self, msg: Scan, _ctx: &mut Self::Context) -> Self::Result {
        let Scan { file, timeout } = msg;
        let result = self
            .rules
            .scan_file(&file, timeout)
            .and_then(|r| Ok(r.iter().map(|rule| rule.identifier.to_string()).collect()));
        ScanResult { file, result }
    }
}