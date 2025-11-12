use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use windows_services::Command;

fn main() {
    std::panic::set_hook(Box::new(|panic_info| {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("C:\\Services\\Tedr\\panic.log")
            .unwrap();
        use std::io::Write;
        let mut file = file;
        writeln!(file, "PANIC: {:?}", panic_info).ok();
    }));

    let file_appender = tracing_appender::rolling::hourly("C:\\logs", "tservice.log");

    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_line_number(true)
        .with_level(true)
        .with_thread_ids(true)
        .compact()
        .try_init()
        .ok();

    let token = tokio_util::sync::CancellationToken::new();
    let c_token = token.child_token();

    let result =
        windows_services::Service::new()
            .can_stop()
            .run(|_service, command| match command {
                Command::Start => {
                    info!("Service starting...");

                    let c_token = c_token.clone();

                    std::thread::spawn(move || {
                        let runtime =
                            tokio::runtime::Runtime::new().expect("Failed to init runtime");

                        runtime.block_on(async {
                            run_service(c_token).await;
                        });
                    });
                }
                Command::Stop => {
                    token.cancel();
                    std::thread::sleep(Duration::from_millis(500));
                    tracing::info!("Service stopped");
                }
                _ => {
                    warn!("Unhandled service command: {command:?}");
                }
            });

    if result.is_err() {
        println!(
            r#"Use service control manager to start service.
            Install:
                > sc create ServiceName binPath= "{}"
            Start:
                > sc start ServiceName
            Query status:
                > sc query ServiceName
            Stop:
                > sc stop ServiceName
            Delete (uninstall):
                > sc delete ServiceName
            "#,
            std::env::current_exe().unwrap().display()
        );
    }
}

async fn run_service(c_token: CancellationToken) {
    loop {
        tokio::select! {
            _ = c_token.cancelled() => {
                info!("Got shutdown signal!");
                break;
            }
            _ = init_service() => {}
        }
    }

    info!("Service loop ended");
}

async fn init_service() {
    info!("Do work....");

    let _ = tokio::time::sleep(Duration::from_secs(5)).await;
}
