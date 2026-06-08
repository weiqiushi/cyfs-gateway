pub use sfo_result::err as js_err;
pub use sfo_result::into_err as into_js_err;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum JSErrorCode {
    Failed,
    JsFailed,
    InvalidPath,
}

pub type JSResult<T> = sfo_result::Result<T, JSErrorCode>;
