use crate::{
    action::Action,
    config::Config,
    database::{Database, DatabaseAction},
    tui::{
        background::Background, components::Component, pages::configs::ConfigsPageAction, Event,
        Tui,
    },
};
use color_eyre::Result;
use crossterm::event::KeyEvent;
use ratatui::prelude::Rect;
use serde::{Deserialize, Serialize};
use std::{path::Path, process::Command, sync::Arc};
use tokio::sync::mpsc;
use tracing::{debug, info};

pub const CACHE_PATH: &str = concat!(env!("HOME"), "/.cache/tuxtape-dashboard");
pub const GIT_PATH: &str = const_format::concatcp!(CACHE_PATH, "/git");
pub const LINUX_REPO_PATH: &str = const_format::concatcp!(GIT_PATH, "/linux");
pub const LINUX_REPO_URL: &str = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git";

pub struct App {
    config: Arc<Config>,
    db: Database,
    background: Background,
    should_quit: bool,
    mode: Mode,
    last_tick_key_events: Vec<KeyEvent>,
    action_tx: mpsc::UnboundedSender<Action>,
    action_rx: mpsc::UnboundedReceiver<Action>,
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Mode {
    #[default]
    /// The Background and Pages are displayed
    Normal,
    /// The TUI aspects of this program are suspended in favor of
    /// displaying another program (such as a text editor) in the terminal
    Suspended,
}

impl App {
    pub async fn new() -> Result<Self> {
        init_linux_repo()?;

        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let config = Arc::new(Config::new()?);
        let db = Database::new(config.clone(), action_tx.clone()).await?;
        Ok(Self {
            config: config.clone(),
            db,
            background: Background::new(config)?,
            should_quit: false,
            mode: Mode::Normal,
            last_tick_key_events: Vec::new(),
            action_tx,
            action_rx,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut tui = Tui::new()?;
        tui.enter()?;

        self.background
            .register_action_handler(self.action_tx.clone())?;

        self.background.init(tui.size()?)?;

        loop {
            self.handle_events(&mut tui).await?;
            self.handle_actions(&mut tui)?;
            if self.should_quit {
                tui.stop()?;
                break;
            }
        }
        tui.exit()?;
        Ok(())
    }

    async fn handle_events(&mut self, tui: &mut Tui) -> Result<()> {
        let Some(event) = tui.next_event().await else {
            return Ok(());
        };
        let action_tx = self.action_tx.clone();
        match event {
            Event::Quit => action_tx.send(Action::Quit)?,
            Event::Tick => action_tx.send(Action::Tick)?,
            Event::Render => action_tx.send(Action::Render)?,
            Event::Resize(x, y) => action_tx.send(Action::Resize(x, y))?,
            Event::Key(key) => self.handle_key_event(key)?,
            _ => {}
        }
        if let Some(action) = self.background.handle_events(Some(event.clone()))? {
            action_tx.send(action)?;
        }
        Ok(())
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        let action_tx = self.action_tx.clone();
        let Some(keymap) = self.config.keybindings.get(&self.mode) else {
            return Ok(());
        };
        match keymap.get(&vec![key]) {
            Some(action) => {
                info!("Got action: {action:?}");
                action_tx.send(action.clone())?;
            }
            _ => {
                // If the key was not handled as a single key action,
                // then consider it for multi-key combinations.
                self.last_tick_key_events.push(key);

                // Check for multi-key combinations
                if let Some(action) = keymap.get(&self.last_tick_key_events) {
                    info!("Got action: {action:?}");
                    action_tx.send(action.clone())?;
                }
            }
        }
        Ok(())
    }

    fn handle_actions(&mut self, tui: &mut Tui) -> Result<()> {
        while let Ok(action) = self.action_rx.try_recv() {
            if action != Action::Tick && action != Action::Render {
                debug!("{action:?}");
            }

            // Handle Actions that require TUI state changes before being pushed downstream
            // (such as suspending the TUI)
            //
            // NOTE: Remove this clippy override when we add a second condition to this block.
            // I anticipate CreateNewConfig will not be the only thing we need to check for here.
            #[allow(clippy::single_match)]
            match action {
                Action::ConfigsPage(ref action) => match action {
                    ConfigsPageAction::CreateNewConfig(_) => {
                        self.suspend(tui)?;
                    }
                },
                _ => {}
            }

            // Forward Action to Background first and see if anything downstream consumes it.
            let unconsumed_action = match self.background.update(action)? {
                Some(action) => action,
                None => continue,
            };

            // Handle Actions that were not consumed by downstream or returned from downstream
            match unconsumed_action {
                Action::Tick => {
                    self.last_tick_key_events.drain(..);
                }
                Action::Suspend => {
                    self.suspend(tui)?;
                }
                Action::Resume => {
                    self.resume(tui)?;
                }
                Action::ClearScreen => {
                    tui.terminal.clear()?;
                }
                Action::Resize(w, h) => {
                    self.handle_resize(tui, w, h)?;
                }
                Action::Render => {
                    self.render(tui)?;
                }
                Action::Database(DatabaseAction::Request(ref request)) => {
                    self.db.handle_request(request)?;
                }
                Action::EditPatchAtPath(ref path) => {
                    // TODO - I see no use in Modes right now. Maybe remove?
                    self.mode = Mode::Suspended;
                    tui.exit()?;
                    edit::edit_file(Path::new(path))?;
                    self.mode = Mode::Normal;
                    tui.enter()?;
                    tui.terminal.clear()?;
                }
                Action::Quit => self.should_quit = true,
                _ => {}
            }
        }

        Ok(())
    }

    fn handle_resize(&mut self, tui: &mut Tui, w: u16, h: u16) -> Result<()> {
        tui.resize(Rect::new(0, 0, w, h))?;
        self.render(tui)?;
        Ok(())
    }

    fn render(&mut self, tui: &mut Tui) -> Result<()> {
        tui.draw(|frame| {
            if let Err(err) = self.background.draw(frame, frame.area()) {
                let _ = self
                    .action_tx
                    .send(Action::Error(format!("Failed to draw: {:?}", err)));
            }
        })?;
        Ok(())
    }

    fn suspend(&mut self, tui: &mut Tui) -> Result<()> {
        self.mode = Mode::Suspended;
        tui.exit()
    }

    fn resume(&mut self, tui: &mut Tui) -> Result<()> {
        self.mode = Mode::Normal;
        tui.enter()?;
        tui.terminal.clear()?;
        Ok(())
    }
}

fn init_linux_repo() -> Result<()> {
    if !Path::new(LINUX_REPO_PATH).exists() {
        println!(
            "Linux repo dir '{}' does not exist. Creating.",
            LINUX_REPO_PATH
        );
        std::fs::create_dir_all(LINUX_REPO_PATH)?;
    }

    if !Path::new(format!("{}/.git", LINUX_REPO_PATH).as_str()).exists() {
        Command::new("git")
            .current_dir(LINUX_REPO_PATH)
            .args(["clone", LINUX_REPO_URL])
            .spawn()?
            .wait()?;
    }

    Ok(())
}
