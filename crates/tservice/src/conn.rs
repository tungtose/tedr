use std::{
    ffi::c_void,
    mem,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use thiserror::Error;
use tracing::{error, info};
use windows::{
    Win32::{Foundation::HANDLE, Storage::InstallableFileSystems::*},
    core::PCWSTR,
};

#[repr(C)]
pub struct DriverMessage {
    pub header: FILTER_MESSAGE_HEADER,
    pub data: [u8; 1024],
}

pub struct KernelConnection {
    port_handle: HANDLE,
    is_connected: bool,
    is_listener_running: Arc<AtomicBool>,
}

#[derive(Error, Debug)]
pub enum KernelConenctionError {
    #[error("Other error: {0}")]
    Other(String),

    #[error(transparent)]
    WinError(#[from] windows::core::Error),
}

type Result<T> = std::result::Result<T, KernelConenctionError>;

impl KernelConnection {
    const PORT_NAME: PCWSTR = windows::core::w!("\\tedr_port");

    pub fn new() -> Self {
        Self {
            port_handle: HANDLE::default(),
            is_connected: false,
            is_listener_running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn connect_kernel(&mut self) -> Result<()> {
        if self.is_connected {
            return Err(KernelConenctionError::Other(
                "Already connected".to_string(),
            ));
        }

        unsafe {
            let port_handle = FilterConnectCommunicationPort(Self::PORT_NAME, 0, None, 0, None)?;

            self.port_handle = port_handle;
            self.is_connected = true;

            info!("Connected to kernel port");
        }

        Ok(())
    }

    pub fn start_message_listener<F>(&self, mut callback: F) -> Result<std::thread::JoinHandle<()>>
    where
        F: FnMut(&DriverMessage) -> Option<Vec<u8>> + Send + 'static,
    {
        if !self.is_connected {
            // TODO: better error handling than Other
            return Err(KernelConenctionError::Other(
                "Try to listen message while there is no connection".to_string(),
            ));
        }

        if self.is_listener_running.load(Ordering::Relaxed) {
            return Err(KernelConenctionError::Other(
                "The listener already running".to_string(),
            ));
        }

        let port_handle = self.port_handle.0 as isize;
        let running = self.is_listener_running.clone();
        running.store(true, Ordering::Relaxed);

        // SAFETY: Communication port handles are thread-safe kernel objects.
        // The handle remains valid as long as KernelConnection is alive.
        let thread_handle = std::thread::spawn(move || {
            info!("Message listener started");
            let port_handle = HANDLE(port_handle as _);

            while running.load(Ordering::Relaxed) {
                let mut message: DriverMessage = unsafe { mem::zeroed() };

                let result = unsafe {
                    // https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filtergetmessage
                    FilterGetMessage(
                        port_handle,
                        &mut message.header,
                        mem::size_of::<DriverMessage>() as u32,
                        None,
                    )
                };

                match result {
                    Ok(_) => {
                        info!(
                            "Received message from kernel: MessageId={}, ReplyLength={}",
                            message.header.MessageId, message.header.ReplyLength
                        );

                        // Try parse message data as string
                        if let Some(null_pos) = message.data.iter().position(|&b| b == 0) {
                            if let Ok(msg_str) = std::str::from_utf8(&message.data[..null_pos]) {
                                info!("Message content: {msg_str}");
                            } else {
                                info!("Message content is not valid UTF-8");
                            }
                        }

                        let _reply_data = callback(&message);

                        // TODO: reply kenel
                    }
                    Err(err) => {
                        let code = err.code().0;
                        match code {
                            -2147024890 => {
                                error!("Invalid handle");
                                break;
                            }
                            -1073741769 => {
                                error!("Port disconnected");
                                break;
                            }
                            _ => error!("FilterGetMessage error: 0x{:08X}", code as u32),
                        }
                    }
                }
            }

            running.store(false, Ordering::Relaxed);
            info!("Message listener stopped");
        });

        Ok(thread_handle)
    }

    pub fn send_message_to_kernel(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.is_connected {
            return Err(KernelConenctionError::Other("No connection".to_string()));
        }

        let mut output_buffer = vec![0u8; 1024];
        let mut bytes_returned: u32 = 0;

        unsafe {
            FilterSendMessage(
                self.port_handle,
                data.as_ptr() as *const c_void,
                data.len() as u32,
                Some(output_buffer.as_mut_ptr() as *mut c_void),
                output_buffer.len() as u32,
                &mut bytes_returned,
            )
        }?;

        output_buffer.truncate(bytes_returned as usize);

        Ok(output_buffer)
    }

    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    pub fn disconnect(&mut self) -> Result<()> {
        info!("Disconnecting port: TODO");

        Ok(())
    }
}

impl Drop for KernelConnection {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}
