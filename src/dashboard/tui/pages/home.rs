use crate::database::*;
use crate::tui::components::Component;
use crate::tui::popups::PopupType::{Alert, CveEditPreview};
use crate::{action::Action, config::Config};
use color_eyre::eyre::eyre;
use color_eyre::Result;
use ratatui::{prelude::*, widgets::*};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::prelude::*;
use std::sync::Arc;
use strum::{Display, EnumCount, EnumIter, FromRepr};
use tokio::sync::mpsc::UnboundedSender;

/// The main page for tuxtape-dashboard. This is where all CVEs will be listed and selectable for editing.
pub struct HomePage {
    command_tx: Option<UnboundedSender<Action>>,
    config: Arc<Config>,
    cves: Option<Vec<Arc<Cve>>>,
    cve_list_state: ListState,
    fetching_cves: bool,
    cve_affects_pane: CveAffectsPane,
    cve_details_pane: CveDetailsPane,
    selected_pane: Pane,
    selected_cve: Option<Arc<Cve>>,
}

impl HomePage {
    pub fn new(config: Arc<Config>) -> Self {
        let selected_cve = None;

        Self {
            command_tx: None,
            config,
            cves: None,
            cve_list_state: ListState::default(),
            fetching_cves: false,
            cve_affects_pane: CveAffectsPane::new(selected_cve.clone()),
            cve_details_pane: CveDetailsPane::new(selected_cve.clone()),
            selected_pane: Pane::CveList,
            selected_cve: None,
        }
    }

    fn build_cve_list(&mut self, cves: Vec<Arc<Cve>>) {
        self.cves = Some(cves);
        self.cve_list_state.select_first();
        self.update_selected_cve();
    }

    fn preview_edit_patch(&self) -> Result<()> {
        if let Some(cves) = &self.cves {
            if let Some(command_tx) = &self.command_tx {
                let selected_row = self
                    .cve_list_state
                    .selected()
                    .expect("A row on the table will always be highlighted");
                let selected_cve = cves
                    .get(selected_row)
                    .expect("The selected row should always align with a CVE instance in the Vec")
                    .clone();

                command_tx.send(Action::Popup(CveEditPreview(selected_cve)))?;

                return Ok(());
            }
        }

        Ok(())
    }

    fn edit_patch(&self, cve_instance: &CveInstance) -> Result<()> {
        let command_tx = match self.command_tx.as_ref() {
            Some(command_tx) => command_tx,
            None => {
                return Err(eyre!(
                    "self.command_tx should always exist by the time this is called"
                ))
            }
        };

        let raw_patch = match &cve_instance.raw_patch {
            Some(patch) => patch,
            None => {
                command_tx.send(Action::Popup(Alert(
                    "This CVE is missing a raw patch, so there's nothing to edit.".to_string(),
                )))?;
                return Ok(());
            }
        };

        let mut patch_file_path = self.config.config.data_dir.clone();
        patch_file_path.push("patches");

        match std::fs::create_dir_all(&patch_file_path) {
            Ok(()) => {}
            Err(e) => {
                command_tx.send(Action::Popup(Alert(
                    format!("Failed to create directories to {:?}.", patch_file_path).to_string(),
                )))?;
                return Err(e.into());
            }
        }

        patch_file_path.push(format!("{}.patch", cve_instance.title));

        let mut file = match File::create(&patch_file_path) {
            Ok(file) => file,
            Err(e) => {
                command_tx.send(Action::Popup(Alert(
                    format!("Failed to create file {:?}", patch_file_path).to_string(),
                )))?;
                return Err(e.into());
            }
        };

        match file.write_all(raw_patch.as_bytes()) {
            Ok(()) => {}
            Err(e) => {
                command_tx.send(Action::Popup(Alert(
                    format!("Failed to write patch to {:?}", patch_file_path).to_string(),
                )))?;
                return Err(e.into());
            }
        };

        let action = Action::EditPatchAtPath(patch_file_path.to_str().unwrap().to_string());
        command_tx.send(action)?;

        Ok(())
    }

    fn update_selected_cve(&mut self) {
        let selection_index = if let Some(selection_index) = self.cve_list_state.selected() {
            selection_index
        } else {
            self.selected_cve = None;
            return;
        };

        let cves = if let Some(cves) = self.cves.as_ref() {
            cves
        } else {
            self.selected_cve = None;
            return;
        };

        if selection_index >= cves.len() {
            self.selected_cve = None;
        } else {
            self.selected_cve = Some(cves[selection_index].clone());
        }
    }
}

impl Component for HomePage {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.command_tx = Some(tx);
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match &action {
            Action::HomePage(action) => match action {
                HomePageAction::EditPatch(cve_instance) => self.edit_patch(cve_instance)?,
            },
            Action::PaneLeft => self.selected_pane = self.selected_pane.previous(),
            Action::PaneRight => self.selected_pane = self.selected_pane.next(),
            Action::Database(DatabaseAction::Response(response)) => match response {
                Response::PopulateTable(cve_instances) => {
                    self.build_cve_list(cve_instances.clone())
                }
                Response::PutKernelConfig {
                    kernel_config_metadata: _,
                    success: _,
                } => {
                    // Do nothing as the corresponding Request was not sent by HomePage
                }
            },
            _ => match self.selected_pane {
                Pane::CveList => match &action {
                    Action::ScrollDown => {
                        if let Some(cves) = &self.cves {
                            self.cve_list_state.select_next();

                            if cves.len()
                                <= self
                                    .cve_list_state
                                    .selected()
                                    .expect("Something should always be selected")
                            {
                                self.cve_list_state.select_first();
                            }

                            self.update_selected_cve();
                        }
                    }
                    Action::ScrollUp => {
                        if let Some(cves) = &self.cves {
                            if self
                                .cve_list_state
                                .selected()
                                .expect("Something should always be selected")
                                == 0
                            {
                                // Note: ListState::select_last() does not work as expected.
                                self.cve_list_state.select(Some(cves.len() - 1));
                            } else {
                                self.cve_list_state.select_previous();
                            }

                            self.update_selected_cve();
                        }
                    }
                    Action::Select => self.preview_edit_patch()?,
                    _ => return Ok(Some(action)),
                },
                Pane::Affects => return self.cve_affects_pane.update(action),
                Pane::Details => return self.cve_details_pane.update(action),
            },
        }

        Ok(None)
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        if let Some(cves) = self.cves.as_ref() {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(15),
                    Constraint::Percentage(25),
                    Constraint::Percentage(60),
                ])
                .split(area);

            let cve_list = List::default()
                .items(cves.iter().map(|cve| cve.id.as_str()))
                .style(Style::new().blue())
                .highlight_style(Style::new().reversed())
                .highlight_symbol(">>")
                .block(
                    match self.selected_pane {
                        Pane::CveList => Block::bordered().style(Style::new().green()),
                        _ => Block::bordered().style(Style::new().white()),
                    }
                    .title("CVEs"),
                );

            frame.render_stateful_widget(cve_list, chunks[0], &mut self.cve_list_state);

            self.cve_affects_pane.draw(
                frame,
                chunks[1],
                self.selected_cve.clone(),
                matches!(self.selected_pane, Pane::Affects),
            )?;

            self.cve_details_pane.draw(
                frame,
                chunks[2],
                self.selected_cve.clone(),
                matches!(self.selected_pane, Pane::Details),
            )?;

            Ok(())
        } else {
            // Display "Loading" text instead of CVEs until they're retrieved from the server
            if !self.fetching_cves {
                if let Some(command_tx) = self.command_tx.as_mut() {
                    command_tx.send(Action::Database(DatabaseAction::Request(
                        Request::PopulateTable(),
                    )))?;
                    self.fetching_cves = true;
                }
            }

            frame.render_widget(Paragraph::new("Loading"), area);
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Display, Serialize, Deserialize)]
pub enum HomePageAction {
    EditPatch(CveInstance),
}

#[derive(EnumIter, EnumCount, FromRepr, Clone, Copy)]
enum Pane {
    CveList,
    Affects,
    Details,
}

impl Pane {
    /// Get the next pane. If there is no next pane, loop around to first.
    fn next(self) -> Self {
        let current_index = self as usize;
        const MAX_INDEX: usize = Pane::COUNT - 1;
        let next_index = match current_index {
            MAX_INDEX => 0,
            _ => current_index + 1,
        };
        Self::from_repr(next_index).unwrap_or(self)
    }

    /// Get the previous pane. If there is no previous pane, loop around to last.
    fn previous(self) -> Self {
        let current_index = self as usize;
        let previous_index = match current_index {
            0 => Pane::COUNT - 1,
            _ => current_index - 1,
        };
        Self::from_repr(previous_index).unwrap_or(self)
    }
}

#[derive(Default)]
struct CveAffectsPane {
    list_state: ListState,
    selected_cve: Option<Arc<Cve>>,
}

impl CveAffectsPane {
    fn new(selected_cve: Option<Arc<Cve>>) -> Self {
        Self {
            list_state: ListState::default(),
            selected_cve,
        }
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match &action {
            Action::ScrollDown => {
                self.list_state.select_next();
                Ok(None)
            }
            Action::ScrollUp => {
                self.list_state.select_previous();
                Ok(None)
            }
            _ => Ok(Some(action)),
        }
    }

    fn draw(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        selected_cve: Option<Arc<Cve>>,
        is_selected: bool,
    ) -> Result<()> {
        if self.selected_cve != selected_cve {
            self.selected_cve = selected_cve;
            self.list_state.select_first();
        }

        if let Some(selected_cve) = self.selected_cve.as_ref() {
            let items: Vec<String> = selected_cve
                .instances
                .iter()
                .flat_map(|instance| {
                    instance
                        .affected_configs
                        .iter()
                        .map(|affected_config| affected_config.config_name.clone())
                        .collect::<Vec<String>>()
                })
                .collect();

            let list = List::new(items).highlight_symbol(">>").block(
                match is_selected {
                    true => Block::bordered().style(Style::new().green()),
                    false => Block::bordered().style(Style::new().white()),
                }
                .title("Affected Configs"),
            );
            frame.render_stateful_widget(list, area, &mut self.list_state);
        }

        Ok(())
    }
}

#[derive(Default)]
struct CveDetailsPane {
    scrollbar_state: ScrollbarState,
    scroll_position: u16,
    selected_cve: Option<Arc<Cve>>,
}

impl CveDetailsPane {
    fn new(selected_cve: Option<Arc<Cve>>) -> Self {
        Self {
            scrollbar_state: ScrollbarState::default(),
            scroll_position: 0,
            selected_cve,
        }
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match &action {
            Action::ScrollDown => {
                self.scroll_position = self.scroll_position.saturating_add(1);
                self.scrollbar_state = self.scrollbar_state.position(self.scroll_position.into());
                Ok(None)
            }
            Action::ScrollUp => {
                self.scroll_position = self.scroll_position.saturating_sub(1);
                self.scrollbar_state = self.scrollbar_state.position(self.scroll_position.into());
                Ok(None)
            }
            _ => Ok(Some(action)),
        }
    }

    fn draw(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        selected_cve: Option<Arc<Cve>>,
        is_selected: bool,
    ) -> Result<()> {
        if self.selected_cve != selected_cve {
            self.selected_cve = selected_cve;
            self.scroll_position = 0;
            self.scrollbar_state = self.scrollbar_state.position(self.scroll_position.into());
        }

        if let Some(cve) = self.selected_cve.as_ref() {
            let not_available_text = "N/A".to_string();

            let severity = if let Some(severity) = cve.severity {
                format!("{:.1}", severity)
            } else {
                not_available_text.clone()
            };

            let items = vec![
                ListItem::new(format!("Severity: {}", severity)),
                ListItem::new(format!(
                    "Attack Vector: {}",
                    cve.attack_vector.as_ref().unwrap_or(&not_available_text)
                )),
                ListItem::new(format!(
                    "Attack Complexity: {}",
                    cve.attack_complexity
                        .as_ref()
                        .unwrap_or(&not_available_text)
                )),
                ListItem::new(format!(
                    "Privileges Required: {}",
                    cve.attack_complexity
                        .as_ref()
                        .unwrap_or(&not_available_text)
                )),
                ListItem::new(format!(
                    "User Interaction: {}",
                    cve.user_interaction.as_ref().unwrap_or(&not_available_text)
                )),
                ListItem::new(format!(
                    "Scope: {}",
                    cve.scope.as_ref().unwrap_or(&not_available_text)
                )),
                ListItem::new(format!(
                    "Confidentiality Impact: {}",
                    cve.confidentiality_impact
                        .as_ref()
                        .unwrap_or(&not_available_text)
                )),
                ListItem::new(format!(
                    "Integrity Impact: {}",
                    cve.integrity_impact.as_ref().unwrap_or(&not_available_text)
                )),
                ListItem::new(format!(
                    "Availability Impact: {}",
                    cve.availability_impact
                        .as_ref()
                        .unwrap_or(&not_available_text)
                )),
            ];

            let block = match is_selected {
                true => Block::bordered().style(Style::new().green()),
                false => Block::bordered().style(Style::new().white()),
            }
            .title("CVE Details");

            let inner_area = block.inner(area);
            frame.render_widget(block, area);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
                .split(inner_area);

            frame.render_widget(
                List::new(items).block(match is_selected {
                    true => Block::bordered().style(Style::new().green()),
                    false => Block::bordered().style(Style::new().white()),
                }),
                chunks[0],
            );

            let cve_description = Paragraph::new(self.get_formatted_description(cve.description()))
                .wrap(Wrap { trim: true })
                .block(
                    match is_selected {
                        true => Block::bordered().style(Style::new().green()),
                        false => Block::bordered().style(Style::new().white()),
                    }
                    .title("Description"),
                )
                .scroll((self.scroll_position, 0));

            // Note: as of ratatui 0.29.0, Paragraph::content_length() is unstable/experimental and
            // is giving slightly wrong values, causing bigger scroll areas than necessary.
            // Currently this is the best solution as we need to know the width of wrapped text,
            // but it should be changed down the line.
            self.scrollbar_state = self
                .scrollbar_state
                .content_length(cve_description.line_count(chunks[1].width));

            frame.render_widget(cve_description, chunks[1]);
            frame.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .symbols(symbols::scrollbar::VERTICAL),
                chunks[1],
                &mut self.scrollbar_state,
            );
        }

        Ok(())
    }

    fn get_formatted_description(&self, description: &str) -> String {
        // Filter out single line breaks (used for email formatting but messes with our display) and replace them with spaces.
        // We shouldn't filter out all line breaks as double line breaks are for splitting paragraphs.
        // Note: the `regex` crate currently does not support lookaround, which is why this is done manually.
        //
        // Also replace tabs with spaces as tabs break the formatting in ratatui.
        let mut formatted_description = String::new();
        let mut chars = description.chars();
        while let Some(char) = chars.next() {
            match char {
                '\n' => {
                    if let Some(next_char) = chars.next() {
                        match next_char {
                            '\n' => {
                                formatted_description.push(char);
                                formatted_description.push('\n');
                            }
                            '\t' => {
                                formatted_description.push(' ');
                            }
                            _ => {
                                formatted_description.push(' ');
                                formatted_description.push(next_char);
                            }
                        }
                    }
                }
                '\t' => formatted_description.push(' '),
                _ => formatted_description.push(char),
            }
        }

        formatted_description
    }
}
