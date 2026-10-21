//! Private-edge BPC–TSK admission executable.

fn main() -> std::process::ExitCode {
    // A panic payload/backtrace can contain driver input; never print it.
    std::panic::set_hook(Box::new(|_| eprintln!("service")));
    match bpc_tsk_service::run_from_args(std::env::args_os().skip(1)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
