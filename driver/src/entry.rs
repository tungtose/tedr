use core::ptr;

use wdk::println;
use wdk_sys::{
    filesystem::{
        FltBuildDefaultSecurityDescriptor, FltCreateCommunicationPort, FltFreeSecurityDescriptor,
        FltRegisterFilter, FltSendMessage, FltStartFiltering, FltUnregisterFilter,
    },
    ntddk::{
        DbgPrint, KeDelayExecutionThread, PsCreateSystemThread, RtlInitUnicodeString,
        RtlSetDaclSecurityDescriptor,
    },
    DRIVER_OBJECT, FLT_PORT_ALL_ACCESS, FLT_REGISTRATION, FLT_REGISTRATION_VERSION, HANDLE,
    LARGE_INTEGER, NTSTATUS, NT_SUCCESS, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE,
    OBJ_KERNEL_HANDLE, PCLIENT_ID, PCUNICODE_STRING, PFLT_FILTER, PFLT_PORT, PSECURITY_DESCRIPTOR,
    PVOID, STATUS_FAIL_CHECK, STATUS_SUCCESS, THREAD_ALL_ACCESS, UNICODE_STRING, USHORT,
    _MODE::KernelMode,
};

use alloc::{ffi::CString, slice, string::String, vec::Vec};

use crate::global;

/// `driver_entry` function required by WDM
///
/// # Panics
/// Can panic from unwraps of `CStrings` used internally
///
/// # Safety
/// Function is unsafe since it dereferences raw pointers passed to it from WDM
// SAFETY: "DriverEntry" is the required symbol name for Windows driver entry points.
// No other function in this compilation unit exports this name, preventing symbol conflicts.
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    // This is an example of directly using DbgPrint binding to print
    let string = CString::new("Hello World 3!\n").unwrap();

    // SAFETY: This is safe because `string` is a valid pointer to a null-terminated
    // string (`CString` guarantees null-termination)
    unsafe {
        DbgPrint(c"%s".as_ptr().cast(), string.as_ptr());
    }

    // Translate UTF16 string to rust string
    let registry_path = String::from_utf16_lossy(unsafe {
        slice::from_raw_parts(
            (*registry_path).Buffer,
            (*registry_path).Length as usize / core::mem::size_of_val(&(*(*registry_path).Buffer)),
        )
    });
    println!("WDM Driver Entry Complete! Driver Registry Parameter Key: {registry_path}");

    println!("[Entry] Init Global state");

    let mut flt_registration: FLT_REGISTRATION = FLT_REGISTRATION::default();
    flt_registration.Size = core::mem::size_of::<FLT_REGISTRATION>() as USHORT;
    flt_registration.Version = FLT_REGISTRATION_VERSION as USHORT; // Version
    flt_registration.Flags = 0;
    flt_registration.FilterUnloadCallback = Some(filter_unload_callback);

    let mut global_filter_handle: PFLT_FILTER = unsafe { core::mem::zeroed() };

    let mut status =
        unsafe { FltRegisterFilter(driver, &flt_registration, &mut global_filter_handle) };

    println!("DBG 4, FltRegisterFilter status: {status}",);

    if NT_SUCCESS(status) {
        println!("Register minifilter success!");
        unsafe {
            global::set_filter_handle(global_filter_handle);
            println!("Saved minifilter handle");

            status = FltStartFiltering(global_filter_handle);

            if !NT_SUCCESS(status) {
                println!("Failed to start minifilter");
                FltUnregisterFilter(global_filter_handle);

                global::set_filter_handle(ptr::null_mut());
                driver.DriverUnload = Some(driver_exit);

                return STATUS_SUCCESS;
            }

            if NT_SUCCESS(status) {
                println!("Start minifilter success");
            }

            // Init comm port
            status = init_comm();

            if NT_SUCCESS(status) {
                println!("Init comm success");
            }

            // Create worker thread: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pscreatesystemthread
            // NTSTATUS PsCreateSystemThread(
            //   [out]           PHANDLE            ThreadHandle,
            //   [in]            ULONG              DesiredAccess,
            //   [in, optional]  POBJECT_ATTRIBUTES ObjectAttributes,
            //   [in, optional]  HANDLE             ProcessHandle,
            //   [out, optional] PCLIENT_ID         ClientId,
            //   [in]            PKSTART_ROUTINE    StartRoutine,
            //   [in, optional]  PVOID              StartContext
            // );

            // let mut obj_attr = OBJECT_ATTRIBUTES::default();
            let mut p_thread_handle: HANDLE = HANDLE::default();

            status = PsCreateSystemThread(
                &mut p_thread_handle,
                THREAD_ALL_ACCESS,
                ptr::null_mut(),
                ptr::null_mut(),
                PCLIENT_ID::default(),
                Some(worker_thread),
                ptr::null_mut(),
            );

            if !NT_SUCCESS(status) {
                println!("ERROR: Failed to spawning kernel thread: PsCreateSystemThread, status: {status}");
            } else {
                global::set_thread_worker_handle(p_thread_handle);
                // TODO: use ObReferenceObjectByHandle to a pointer to thread object.
                // So we can implement properly shutdown whith ObDereferenceObject
            }
        }
    }

    driver.DriverUnload = Some(driver_exit);

    // It is much better to use the println macro that has an implementation in
    // wdk::print.rs to call DbgPrint. The println! implementation in
    // wdk::print.rs has the same features as the one in std (ex. format args
    // support).

    STATUS_SUCCESS
}

unsafe extern "C" fn init_comm() -> NTSTATUS {
    println!("[COM] starting");
    let mut p_sec_desc: PSECURITY_DESCRIPTOR = ptr::null_mut();

    println!("[COM] Dbg 0");
    let mut status =
        unsafe { FltBuildDefaultSecurityDescriptor(&mut p_sec_desc, FLT_PORT_ALL_ACCESS) };

    println!("[COM] FltBuildDefaultSecurityDescriptor: {status}");

    if !NT_SUCCESS(status) {
        println!("[COM] FltBuildDefaultSecurityDescriptor failed.status: {status}");
        return STATUS_FAIL_CHECK;
    }

    if NT_SUCCESS(status) {
        let acl = ptr::null_mut();
        status = unsafe { RtlSetDaclSecurityDescriptor(p_sec_desc, 1, acl as _, 0) };

        if NT_SUCCESS(status) {
            println!("[COM] RtlSetDaclSecurityDescriptor success");
        } else {
            println!("[COM] RtlSetDaclSecurityDescriptor failed: {status}");
        }
    }

    println!("[COM] Dbg 2");

    // Init port name
    let mut wide: Vec<u16> = "\\tedr_port"
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();

    println!("[COM] Dbg 3");

    let mut port_name_dst: UNICODE_STRING = unsafe { core::mem::zeroed() };
    unsafe { RtlInitUnicodeString(&mut port_name_dst, wide.as_mut_ptr()) };

    println!("[COM] Dbg 4");

    let mut obj_attr = OBJECT_ATTRIBUTES {
        Length: core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: ptr::null_mut(),
        ObjectName: &mut port_name_dst,
        Attributes: OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: p_sec_desc,
        SecurityQualityOfService: ptr::null_mut(),
    };

    println!("[COM] Dbg 5");

    let m_port: PFLT_PORT = ptr::null_mut();

    unsafe {
        if let Some(filter_handle) = global::get_filter_handle() {
            status = FltCreateCommunicationPort(
                filter_handle,
                m_port as _,
                &mut obj_attr,
                ptr::null_mut(),
                Some(connect_notify),
                Some(disconnect_notify),
                None,
                1,
            );

            println!("[COM] Dbg 6");

            global::set_filter_port(m_port);

            FltFreeSecurityDescriptor(p_sec_desc);

            println!("[COM] Dbg 7");

            if NT_SUCCESS(status) {
                println!("FltCreateCommunicationPort success",);
            } else {
                println!("FltCreateCommunicationPort failed .status: {status}",);
            }
        }
    }

    STATUS_SUCCESS
}

// Called when user-mode connects
unsafe extern "C" fn connect_notify(
    client_port: PFLT_PORT,
    _server_port_cookie: PVOID,
    _connection_context: PVOID,
    _size_of_context: u32,
    connection_port_cookie: *mut PVOID,
) -> NTSTATUS {
    println!("[Driver] Client connected");

    // Save client port for sending messages later
    global::set_client_port(client_port);

    // No connection context needed
    unsafe { *connection_port_cookie = ptr::null_mut() }

    STATUS_SUCCESS
}

// Disconnect callback
unsafe extern "C" fn disconnect_notify(_connection_cookie: PVOID) {
    println!("[Driver] Client disconnected");

    // TODO: Clear client port
    // unsafe { GLOBAL_CLIENT_PORT = None };
}

unsafe extern "C" fn filter_unload_callback(_flags: u32) -> NTSTATUS {
    STATUS_SUCCESS
}

unsafe extern "C" fn worker_thread(_context: PVOID) {
    println!("[Worker] Thread started");

    loop {
        // Checking exit signal
        if global::should_worker_exit() {
            println!("[Worker] exit signal received, terminating thread");
            break;
        }

        // wait for 5 secs
        let mut interval = LARGE_INTEGER::default();
        // kernel unit: 100ns
        interval.QuadPart = -5 * 10_000_000;

        unsafe {
            let _ = KeDelayExecutionThread(KernelMode as i8, 1, &mut interval);
        }

        // Checking exit signal again after wait. Will remove this soon
        if global::should_worker_exit() {
            println!("[Worker] exit signal received, terminating thread");
            break;
        }

        // Check if connection is connected
        if global::get_filter_handle().is_none() || global::get_client_port().is_none() {
            println!("[Worker] client not connected skip");
            continue;
        }

        // if unsafe { GLOBAL_CLIENT_PORT.is_none() } {
        //     println!("[Worker] client not connected skip");
        //     continue;
        // }

        // Send "Hello world" message
        let message = b"Hello world\0";

        // API: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltsendmessage
        // NTSTATUS FLTAPI FltSendMessage(
        //   [in]            PFLT_FILTER    Filter,
        //   [in]            PFLT_PORT      *ClientPort,
        //   [in]            PVOID          SenderBuffer,
        //   [in]            ULONG          SenderBufferLength,
        //   [out, optional] PVOID          ReplyBuffer,
        //   [in, out]       PULONG         ReplyLength,
        //   [in, optional]  PLARGE_INTEGER Timeout
        // );

        println!("[Worker] Sending Hello World");
        if let Some(filter_handle) = global::get_filter_handle() {
            if let Some(mut client_port) = global::get_client_port() {
                let status = unsafe {
                    FltSendMessage(
                        filter_handle,
                        &mut client_port,
                        message.as_ptr() as _,
                        message.len() as u32,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                    )
                };

                if NT_SUCCESS(status) {
                    println!("[Worker] Message sent successfully");
                } else {
                    println!("[Worker] Failed to send message: {:#x}", status);
                }
            };
        }

        // TODO: properly exit
    }
}

extern "C" fn driver_exit(_driver: *mut DRIVER_OBJECT) {
    if let Some(filter_handle) = global::get_filter_handle() {
        unsafe { FltUnregisterFilter(filter_handle) };
    }

    println!("Goodbye World!");
    println!("Driver Exit Complete!");
}
