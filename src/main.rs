use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    match closeenv::run_cli(env::args().collect()) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(2)
        }
    }
}
