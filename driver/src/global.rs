use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use wdk_sys::{HANDLE, PFLT_FILTER, PFLT_PORT, _FLT_FILTER, _FLT_PORT};

pub struct FltGlobalState {
    filter_handle: AtomicPtr<_FLT_FILTER>,
    filter_port: AtomicPtr<_FLT_PORT>,
    client_port: AtomicPtr<_FLT_PORT>,
    thread_worker_handle: AtomicPtr<core::ffi::c_void>,
}

impl FltGlobalState {
    const fn new() -> Self {
        Self {
            filter_handle: AtomicPtr::new(null_mut()),
            filter_port: AtomicPtr::new(null_mut()),
            client_port: AtomicPtr::new(null_mut()),
            thread_worker_handle: AtomicPtr::new(null_mut()),
        }
    }
}

pub static GLOBAL_STATE: FltGlobalState = FltGlobalState::new();
pub static WORKER_SHOULD_EXIT: AtomicBool = AtomicBool::new(false);

pub fn set_filter_handle(handle: PFLT_FILTER) {
    GLOBAL_STATE.filter_handle.store(handle, Ordering::Release);
}

pub fn set_filter_port(port: PFLT_PORT) {
    GLOBAL_STATE.filter_port.store(port, Ordering::Release);
}

pub fn set_client_port(port: PFLT_PORT) {
    GLOBAL_STATE.client_port.store(port, Ordering::Release);
}

pub fn set_thread_worker_handle(handle: HANDLE) {
    GLOBAL_STATE
        .thread_worker_handle
        .store(handle as *mut _, Ordering::Release);
}

// Getters
pub fn get_filter_handle() -> Option<PFLT_FILTER> {
    let ptr = GLOBAL_STATE.filter_handle.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

pub fn get_filter_port() -> Option<PFLT_PORT> {
    let ptr = GLOBAL_STATE.filter_port.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

pub fn get_client_port() -> Option<PFLT_PORT> {
    let ptr = GLOBAL_STATE.client_port.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

pub fn get_thread_worker_handle() -> Option<HANDLE> {
    let ptr = GLOBAL_STATE.thread_worker_handle.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(ptr as HANDLE)
    }
}

pub fn signal_worker_exit() {
    WORKER_SHOULD_EXIT.store(true, Ordering::Release);
}

pub fn should_worker_exit() -> bool {
    WORKER_SHOULD_EXIT.load(Ordering::Acquire)
}
