use core::ptr;

use wdk::println;

use wdk_sys::{
    _KWAIT_REASON::Executive,
    _MODE::KernelMode,
    DRIVER_OBJECT, FLT_FILESYSTEM_TYPE, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS,
    FLT_INSTANCE_SETUP_FLAGS, FLT_INSTANCE_TEARDOWN_FLAGS, FLT_PORT_ALL_ACCESS, FLT_REGISTRATION,
    FLT_REGISTRATION_VERSION, HANDLE, LARGE_INTEGER, NT_SUCCESS, NTSTATUS, OBJ_CASE_INSENSITIVE,
    OBJ_KERNEL_HANDLE, OBJECT_ATTRIBUTES, PCFLT_RELATED_OBJECTS, PCLIENT_ID, PCUNICODE_STRING,
    PETHREAD, PFLT_FILTER, PFLT_PORT, PSECURITY_DESCRIPTOR, PVOID, STATUS_FAIL_CHECK,
    STATUS_SUCCESS, THREAD_ALL_ACCESS, ULONG, UNICODE_STRING, USHORT,
    filesystem::{
        FltBuildDefaultSecurityDescriptor, FltCloseClientPort, FltCloseCommunicationPort,
        FltCreateCommunicationPort, FltFreeSecurityDescriptor, FltRegisterFilter, FltSendMessage,
        FltStartFiltering, FltUnregisterFilter,
    },
    ntddk::{
        DbgPrint, KeDelayExecutionThread, KeWaitForSingleObject, ObReferenceObjectByHandle,
        ObfDereferenceObject, PsCreateSystemThread, RtlInitUnicodeString,
        RtlSetDaclSecurityDescriptor, ZwClose,
    },
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
    flt_registration.InstanceSetupCallback = Some(instance_setup);
    flt_registration.InstanceQueryTeardownCallback = Some(instance_query_teardown);
    flt_registration.InstanceTeardownStartCallback = Some(instance_teardown_start);
    flt_registration.InstanceTeardownCompleteCallback = Some(instance_teardown_complete);

    let mut global_filter_handle: PFLT_FILTER = unsafe { core::mem::zeroed() };

    let mut status =
        unsafe { FltRegisterFilter(driver, &flt_registration, &mut global_filter_handle) };

    println!("DBG 4, FltRegisterFilter status: {status}",);

    if NT_SUCCESS(status) {
        println!("Register minifilter success!");
        unsafe {
            status = FltStartFiltering(global_filter_handle);

            global::set_filter_handle(global_filter_handle);
            println!("Saved minifilter handle");

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
                println!(
                    "ERROR: Failed to spawning kernel thread: PsCreateSystemThread, status: {status}"
                );
            } else {
                let mut thread_object: PETHREAD = ptr::null_mut();

                println!("Create Kernel Thread success");

                let obj_status = ObReferenceObjectByHandle(
                    p_thread_handle,
                    THREAD_ALL_ACCESS,
                    ptr::null_mut(),
                    KernelMode as i8,
                    &mut thread_object as *mut _ as *mut PVOID,
                    ptr::null_mut(),
                );

                println!("ObReferenceObjectByHandle status: {obj_status}");

                if NT_SUCCESS(obj_status) {
                    global::set_thread_worker_handle(thread_object);
                    println!("Setted thread handle");
                }

                status = ZwClose(p_thread_handle);

                println!("ZwClose status: {status}");
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

// ====== INSTANCES CALL BACK =========
unsafe extern "C" fn instance_setup(
    _flt_object: PCFLT_RELATED_OBJECTS,
    _flags: FLT_INSTANCE_SETUP_FLAGS,
    _volume_device_type: ULONG,
    _volume_file_system_type: FLT_FILESYSTEM_TYPE,
) -> NTSTATUS {
    println!("[Instance] Setup");

    // TODO

    STATUS_SUCCESS
}

unsafe extern "C" fn instance_query_teardown(
    _flt_object: PCFLT_RELATED_OBJECTS,
    _flag: FLT_INSTANCE_QUERY_TEARDOWN_FLAGS,
) -> NTSTATUS {
    println!("[Instance] Query teardown");

    // TODO
    STATUS_SUCCESS
}

unsafe extern "C" fn instance_teardown_start(
    _flt_object: PCFLT_RELATED_OBJECTS,
    _reason: FLT_INSTANCE_TEARDOWN_FLAGS,
) {
    println!("[Instance] Teardown start");
}

unsafe extern "C" fn instance_teardown_complete(
    _flt_object: PCFLT_RELATED_OBJECTS,
    _reason: FLT_INSTANCE_TEARDOWN_FLAGS,
) {
    println!("[Instance] Teardown complete");
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

    let mut m_port: PFLT_PORT = ptr::null_mut();

    unsafe {
        if let Some(filter_handle) = global::get_filter_handle() {
            status = FltCreateCommunicationPort(
                filter_handle,
                &mut m_port,
                &mut obj_attr,
                ptr::null_mut(),
                Some(connect_notify),
                Some(disconnect_notify),
                None,
                1,
            );

            println!("[COM] FltCreateCommunicationPort status: {status}");

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
    println!("[Unload Filter] Called");
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
        if let Some(filter_handle) = global::get_filter_handle()
            && let Some(mut client_port) = global::get_client_port()
        {
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
        }
    }
}

pub fn stop_worker_thread() {
    println!("[Driver] Stopping worker thread");

    // Signal thread to exist
    global::signal_worker_exit();

    // Wait for the thread to finish
    if let Some(thread_object) = global::get_thread_worker_handle() {
        println!("[Driver] waiting for worker thread to exit");

        let mut timeout = LARGE_INTEGER::default();
        timeout.QuadPart = -10 * 10_000_000; // 10 secs

        let status = unsafe {
            KeWaitForSingleObject(
                thread_object as PVOID,
                Executive,
                KernelMode as i8,
                0,
                &mut timeout,
            )
        };

        if NT_SUCCESS(status) {
            println!("[Driver] Worker thread exited successfully");
        } else {
            println!("[Driver] Worker thread wait returned: {:#x}", status);
        }

        // dereferences the thread objet
        unsafe { ObfDereferenceObject(thread_object as PVOID) };
        global::set_thread_worker_handle(ptr::null_mut());
    }

    println!("[Driver] Worker thread cleanup complete");
}

extern "C" fn driver_exit(_driver: *mut DRIVER_OBJECT) {
    stop_worker_thread();

    if let Some(server_port) = global::get_filter_port() {
        println!("[Driver] Server port found, closing...");
        unsafe { FltCloseCommunicationPort(server_port) };
        global::set_filter_port(ptr::null_mut());
        println!("[Driver] Server port closed");
    }

    if let Some(filter_handle) = global::get_filter_handle() {
        if let Some(mut client_port) = global::get_client_port() {
            unsafe { FltCloseClientPort(filter_handle, &mut client_port) };
            println!("[Driver] Closed Client Port");

            global::set_client_port(ptr::null_mut());
        }

        unsafe { FltUnregisterFilter(filter_handle) };
        println!("[Driver] Unregister Filter Done");
        global::set_filter_handle(ptr::null_mut());
    }

    println!("Driver Exit Complete!");
}
