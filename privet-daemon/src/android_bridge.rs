//! JNI entry points for the embedded daemon (Android only).
//!
//! The app declares `PrivetDaemonNative` with `external fun privetdRun(configPath,
//! ipcPath): Int` and `external fun privetdShutdown()`, then calls them on a
//! dedicated daemon thread. Symbol names follow the JNI mangling convention for
//! package `app.privet.privet_app` / class `PrivetDaemonNative` (`_` -> `_1`).

use std::path::PathBuf;

use jni::objects::{JClass, JString};
use jni::sys::jint;
use jni::JNIEnv;

use crate::run;

/// Runs the daemon to completion on the calling thread (the app's daemon
/// thread). Returns 0 on a clean stop, 1 on error.
#[no_mangle]
pub extern "system" fn Java_app_privet_privet_1app_PrivetDaemonNative_privetdRun(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
    ipc_path: JString,
) -> jint {
    let config = env
        .get_string(&config_path)
        .ok()
        .map(|s| PathBuf::from(s.to_string_lossy().into_owned()));
    let ipc = env
        .get_string(&ipc_path)
        .ok()
        .map(|s| PathBuf::from(s.to_string_lossy().into_owned()));
    run::reset_shutdown();
    match run::run_blocking(config, ipc) {
        Ok(()) => 0,
        Err(error) => {
            tracing::error!(%error, "embedded privetd stopped with an error");
            1
        }
    }
}

/// Asks the running daemon thread to shut down cleanly.
#[no_mangle]
pub extern "system" fn Java_app_privet_privet_1app_PrivetDaemonNative_privetdShutdown(
    _env: JNIEnv,
    _class: JClass,
) {
    run::request_shutdown();
}
