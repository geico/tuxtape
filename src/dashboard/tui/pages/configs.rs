use crate::action::Action;
use crate::app::LINUX_REPO_PATH;
use crate::database::Request::PutKernelConfig;
use crate::database::{DatabaseAction, KernelConfig, KernelConfigMetadata, KernelVersion};
use crate::tui::components::Component;
use color_eyre::eyre::eyre;
use color_eyre::Result;
use ratatui::layout::Rect;
use ratatui::prelude::*;
use ratatui::widgets::*;
use ratatui::Frame;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;
use tokio::sync::mpsc::UnboundedSender;

/// The page for creating new configs (and eventually for viewing already-made configs)
#[derive(Default)]
pub struct ConfigsPage {
    command_tx: Option<UnboundedSender<Action>>,
    versions_list_state: ListState,
    kernel_versions: Vec<KernelVersion>,
}

impl ConfigsPage {
    pub fn new() -> Self {
        let git_versions = Command::new("git")
            .current_dir(LINUX_REPO_PATH)
            .arg("--no-pager")
            .arg("tag")
            .args(["--sort", "-v:refname"])
            .output()
            .unwrap()
            .stdout;

        let mut kernel_version_strings: Vec<String> = Vec::new();
        let mut current_string = "".to_string();
        for character in git_versions {
            match character {
                b'\n' => {
                    let binding = &current_string;
                    if !binding.contains("-") {
                        // Filter out strings that are in w.x.y.z format (occured in v2.x)
                        if current_string.chars().filter(|c| *c == '.').count() < 3 {
                            kernel_version_strings.push(current_string.clone());
                        }
                    }
                    current_string.clear();
                }
                b'v' => {
                    // Don't push 'v' into our array as we only want version numbers
                }
                _ => {
                    current_string.push(
                        char::from_u32(character.into())
                            .expect("Git should never give us a bad value"),
                    );
                }
            }
        }

        let kernel_versions = Vec::from_iter(
            kernel_version_strings
                .iter()
                .flat_map(|git_version_str| str_to_kernel_version(git_version_str)),
        );

        let mut list_state = ListState::default();
        list_state.select_first();

        Self {
            command_tx: None,
            versions_list_state: list_state,
            kernel_versions,
        }
    }
}

impl Component for ConfigsPage {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.command_tx = Some(tx);

        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match action {
            Action::ScrollDown => {
                self.versions_list_state.select_next();
            }
            Action::ScrollUp => {
                self.versions_list_state.select_previous();
            }
            Action::Select => {
                // Defer CreateNewConfig action because the TUI must be suspended first
                if let Some(command_tx) = &self.command_tx {
                    let kernel_version = self.kernel_versions[self
                        .versions_list_state
                        .selected()
                        .expect("Something is always selected")];
                    command_tx.send(Action::ConfigsPage(ConfigsPageAction::CreateNewConfig(
                        kernel_version,
                    )))?;
                }
            }
            Action::ConfigsPage(ref action) => match action {
                ConfigsPageAction::CreateNewConfig(kernel_version) => {
                    let config = create_new_config(kernel_version)?;
                    if let Some(command_tx) = &self.command_tx {
                        command_tx.send(Action::Resume)?;
                        command_tx.send(Action::Database(DatabaseAction::Request(
                            PutKernelConfig(config),
                        )))?;
                    }
                }
            },
            _ => return Ok(Some(action)),
        }
        Ok(Some(action))
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        let list: List<'_> = List::new(
            self.kernel_versions
                .iter()
                .map(kernel_version_to_string)
                .clone(),
        )
        .highlight_symbol(">>")
        .highlight_style(Style::new().reversed());
        frame.render_stateful_widget(list, area, &mut self.versions_list_state);
        Ok(())
    }
}

fn create_new_config(kernel_version: &KernelVersion) -> Result<KernelConfig> {
    // TODO (MVP) - make this configurable
    let config_name = format!(
        "{}-tuxtape-poc.config",
        kernel_version_to_string(kernel_version)
    );

    checkout_kernel_version(kernel_version)?;

    Command::new("make")
        .arg("menuconfig")
        .current_dir(LINUX_REPO_PATH)
        .spawn()?
        .wait()?;

    let config_path = PathBuf::from(LINUX_REPO_PATH).join(".config");
    if !config_path.is_file() {
        return Err(eyre!(".config does not exist at path {:?}.", config_path));
    }

    let config_file = std::fs::read_to_string(config_path)?;
    let metadata = KernelConfigMetadata {
        config_name,
        kernel_version: Some(*kernel_version),
    };
    let kernel_config = KernelConfig {
        metadata: Some(metadata),
        config_file,
    };

    Ok(kernel_config)
}

fn checkout_kernel_version(kernel_version: &KernelVersion) -> Result<()> {
    // Clean repo so checkout goes smoothly
    let result = Command::new("make")
        .current_dir(LINUX_REPO_PATH)
        .arg("distclean")
        .spawn()?
        .wait()?;

    match result.success() {
        true => {}
        false => return Err(eyre!("Failed to run make distclean on Linux repo.",)),
    };

    // Checkout version at tag matching kernel_version
    let tag_string = kernel_version_to_tag_string(kernel_version);
    let result = Command::new("git")
        .current_dir(LINUX_REPO_PATH)
        .args(["checkout", tag_string.as_str()])
        .spawn()?
        .wait_with_output()?;

    match result.status.success() {
        true => Ok(()),
        false => Err(eyre!(
            "Git failed to checkout tag {} with output: {}",
            tag_string,
            String::from_utf8(result.stdout)?
        )),
    }
}

fn str_to_kernel_version(kernel_version_str: &str) -> Option<KernelVersion> {
    let split = kernel_version_str.split('.');
    let mut major = None;
    let mut minor = None;
    let mut patch = None;
    for part in split {
        if major.is_none() {
            major = if let Ok(major) = part.parse::<u32>() {
                Some(major)
            } else {
                return None;
            };
        } else if minor.is_none() {
            minor = if let Ok(minor) = part.parse::<u32>() {
                Some(minor)
            } else {
                return None;
            };
        } else if patch.is_none() {
            patch = if let Ok(patch) = part.parse::<u32>() {
                Some(patch)
            } else {
                return None;
            };
        } else {
            // If there are more than 3 parts (major, minor, patch) in the version number, it's invalid.
            // This appears to only happen on v2.x.
            return None;
        }
    }

    let major = major?;
    let minor = minor?;

    Some(KernelVersion {
        major,
        minor,
        patch,
    })
}

fn kernel_version_to_tag_string(kernel_version: &KernelVersion) -> String {
    format!(
        "v{}.{}{}",
        kernel_version.major,
        kernel_version.minor,
        match kernel_version.patch {
            Some(patch) => format!(".{patch}"),
            None => "".to_string(),
        }
    )
}

fn kernel_version_to_string(kernel_version: &KernelVersion) -> String {
    format!(
        "{}.{}{}",
        kernel_version.major,
        kernel_version.minor,
        match kernel_version.patch {
            Some(patch) => format!(".{patch}"),
            None => "".to_string(),
        }
    )
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConfigsPageAction {
    CreateNewConfig(KernelVersion),
}
