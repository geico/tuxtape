use crate::app::App;
use clap::Parser;
use cli::Cli;
use color_eyre::Result;

mod action;
mod app;
mod cli;
mod config;
mod database;
mod errors;
mod logging;
mod tui;

#[tokio::main]
async fn main() -> Result<()> {
    crate::errors::init()?;
    crate::logging::init()?;

    // TODO - decide if we should remove CLI args entirely
    let _args = Cli::parse();
    let mut app = App::new().await?;
    app.run().await?;
    Ok(())
}
