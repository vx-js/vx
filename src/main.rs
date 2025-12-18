use clap::Parser;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = vx::cli::Cli::parse();
    match vx::app::run(cli).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
