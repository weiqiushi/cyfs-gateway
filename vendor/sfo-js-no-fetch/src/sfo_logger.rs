use crate::Trace;
use boa_engine::{Context, JsResult};
use boa_macros::Finalize;
use boa_runtime::{ConsoleState, Logger};
use std::sync::{Arc, Mutex};
use boa_gc::Tracer;

#[derive(Debug, Clone)]
pub struct LogCache {
    entries: Arc<Mutex<Vec<String>>>,
}

unsafe impl boa_gc::Trace for LogCache {
    unsafe fn trace(&self, _tracer: &mut Tracer) {
    }

    unsafe fn trace_non_roots(&self) {
    }

    fn run_finalizer(&self) {
    }
}

impl boa_gc::Finalize for LogCache {
    fn finalize(&self) {
    }
}

impl LogCache {
    pub fn new() -> Self {
        LogCache {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn push(&self, msg: String) {
        let mut cache = self.entries.lock().unwrap();
        cache.push(msg);
    }

    pub fn get_logs(&self) -> Vec<String> {
        let cache = self.entries.lock().unwrap();
        cache.clone()
    }

    pub fn clear(&self) {
        let mut cache = self.entries.lock().unwrap();
        cache.clear();
    }

    pub fn len(&self) -> usize {
        let cache = self.entries.lock().unwrap();
        cache.len()
    }

    pub fn is_empty(&self) -> bool {
        let cache = self.entries.lock().unwrap();
        cache.is_empty()
    }
}

#[derive(Debug, Trace, Finalize)]
pub struct SfoLogger {
    pub log_cache: LogCache,
}

impl SfoLogger {
    pub fn new(log_cache: LogCache) -> Self {
        SfoLogger {
            log_cache,
        }
    }
}

impl Logger for SfoLogger {
    fn log(&self, msg: String, state: &ConsoleState, _context: &mut Context) -> JsResult<()> {
        let indent = state.indent();
        let formatted_msg = format!("{msg:>indent$}");
        log::info!("{}", formatted_msg);

        // 添加到缓存
        self.log_cache.push(formatted_msg);
        Ok(())
    }

    fn info(&self, msg: String, state: &ConsoleState, _context: &mut Context) -> JsResult<()> {
        let indent = state.indent();
        let formatted_msg = format!("{msg:>indent$}");
        log::info!("{}", formatted_msg);

        // 添加到缓存
        self.log_cache.push(formatted_msg);
        Ok(())
    }

    fn warn(&self, msg: String, state: &ConsoleState, _context: &mut Context) -> JsResult<()> {
        let indent = state.indent();
        let formatted_msg = format!("{msg:>indent$}");
        log::warn!("{}", formatted_msg);

        // 添加到缓存
        self.log_cache.push(formatted_msg);
        Ok(())
    }

    fn error(&self, msg: String, state: &ConsoleState, _context: &mut Context) -> JsResult<()> {
        let indent = state.indent();
        let formatted_msg = format!("{msg:>indent$}");
        log::error!("{}", formatted_msg);

        // 添加到缓存
        self.log_cache.push(formatted_msg);
        Ok(())
    }
}
