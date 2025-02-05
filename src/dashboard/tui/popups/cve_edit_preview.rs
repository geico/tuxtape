/// The Popup that displays when a CVE is selected to be edited.
use super::PopupFrame;
use crate::database::CveInstance;
use crate::tui::pages::home::HomePageAction::EditPatch;
use crate::{
    action::Action,
    database::{Cve, KernelVersion},
    tui::components::Component,
};
use color_eyre::Result;
use ratatui::{prelude::*, widgets::*};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use strum::{EnumCount, EnumIter, FromRepr};
use tokio::sync::mpsc::UnboundedSender;

pub struct CveEditPreview<'a> {
    frame: PopupFrame<'a>,
    cve: Arc<Cve>,
    cve_instances_table_state: TableState,
    selected_cve_instance: Rc<RefCell<CveInstance>>,
    selected_pane: Pane,
    affects_pane: AffectsPane,
    command_tx: UnboundedSender<Action>,
}

impl CveEditPreview<'_> {
    pub fn new(cve: Arc<Cve>, command_tx: UnboundedSender<Action>) -> Self {
        let frame = PopupFrame::new(cve.id.clone(), None);

        let mut cve_instances_table_state = TableState::default();
        cve_instances_table_state.select_first();

        let selected_cve_instance = Rc::new(RefCell::new(cve.instances[0].clone()));

        Self {
            frame,
            cve,
            cve_instances_table_state,
            selected_cve_instance: selected_cve_instance.clone(),
            selected_pane: Pane::InstancePane,
            affects_pane: AffectsPane::new(selected_cve_instance),
            command_tx,
        }
    }
}

impl Component for CveEditPreview<'_> {
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        self.frame.draw(frame, area)?;

        let cve_instances_table_rows: Vec<Row> = self
            .cve
            .instances
            .iter()
            .map(|cve_instance| {
                Row::new(vec![
                    cve_instance.title.clone(),
                    if let Some(introduced_version) = &cve_instance.introduced {
                        kernel_version_to_string(introduced_version)
                    } else {
                        "NULL".to_string()
                    },
                    if let Some(fixed_version) = &cve_instance.fixed {
                        kernel_version_to_string(fixed_version)
                    } else {
                        "NULL".to_string()
                    },
                ])
            })
            .collect();

        let cve_instances_table_widths = vec![
            Constraint::Percentage(60),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ];

        let cve_instances_table = Table::new(cve_instances_table_rows, cve_instances_table_widths)
            .highlight_symbol(">>")
            .row_highlight_style(Style::new().reversed())
            .header(
                Row::new(vec!["CVE Instance", "Introduced", "Fixed"])
                    .style(Style::new().bg(Color::Blue).fg(Color::White)),
            )
            .block(
                Block::bordered()
                    .title_top(Line::from("CVE Instance").centered())
                    .style(match self.selected_pane {
                        Pane::InstancePane => Style::new().green(),
                        _ => Style::new().white(),
                    }),
            );

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(self.frame.get_content_area(area));

        frame.render_stateful_widget(
            cve_instances_table,
            chunks[0],
            &mut self.cve_instances_table_state,
        );

        self.affects_pane.draw(
            frame,
            chunks[1],
            matches!(self.selected_pane, Pane::AffectsPane),
        )
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        // Consume navigation actions, pass through all else
        match action {
            Action::Select => {
                let selected_instance = self.cve.instances[self
                    .cve_instances_table_state
                    .selected()
                    .expect("Something will always be selected")]
                .clone();

                self.command_tx
                    .send(Action::HomePage(EditPatch(selected_instance)))?;
            }
            Action::PaneLeft => self.selected_pane = self.selected_pane.previous(),
            Action::PaneRight => self.selected_pane = self.selected_pane.next(),
            Action::TabLeft | Action::TabRight => return Ok(None),
            Action::ScrollDown | Action::ScrollUp => match self.selected_pane {
                Pane::InstancePane => {
                    match action {
                        Action::ScrollDown => {
                            self.cve_instances_table_state.select_next();
                            if self.cve.instances.len()
                                <= self.cve_instances_table_state.selected().unwrap()
                            {
                                self.cve_instances_table_state.select_first();
                            }

                            self.selected_cve_instance.replace(
                                self.cve.instances[self
                                    .cve_instances_table_state
                                    .selected()
                                    .expect("An item will always be selected")]
                                .clone(),
                            );
                        }
                        Action::ScrollUp => {
                            if self.cve_instances_table_state.selected().unwrap() == 0 {
                                // Note: ListState::select_last() does not work as expected.
                                self.cve_instances_table_state
                                    .select(Some(self.cve.instances.len() - 1));
                            } else {
                                self.cve_instances_table_state.select_previous();
                            }

                            self.selected_cve_instance.replace(
                                self.cve.instances[self
                                    .cve_instances_table_state
                                    .selected()
                                    .expect("An item will always be selected")]
                                .clone(),
                            );
                        }
                        _ => {} // This can't get hit but appeases the compiler
                    }
                }
                Pane::AffectsPane => return self.affects_pane.update(action),
            },
            _ => return Ok(Some(action)),
        }
        Ok(None)
    }
}

#[derive(EnumIter, EnumCount, FromRepr, Clone, Copy)]
enum Pane {
    InstancePane,
    AffectsPane,
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

struct AffectsPane {
    cve_instance: Rc<RefCell<CveInstance>>,
    affects_list_state: ListState,
}

impl AffectsPane {
    fn new(cve_instance: Rc<RefCell<CveInstance>>) -> Self {
        let mut affects_list_state = ListState::default();
        affects_list_state.select_first();

        Self {
            cve_instance,
            affects_list_state,
        }
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect, is_selected: bool) -> Result<()> {
        let cve_instance = self.cve_instance.borrow();

        let cve_instance_affects_items: Vec<&str> = cve_instance
            .affected_configs
            .iter()
            .map(|affected_config| affected_config.config_name.as_str())
            .collect();

        let cve_instance_affects_list = List::new(cve_instance_affects_items)
            .block(
                match is_selected {
                    true => Block::bordered().style(Style::new().green()),
                    false => Block::bordered().style(Style::new().white()),
                }
                .title("Affected Configs"),
            )
            .highlight_symbol(">>");

        frame.render_stateful_widget(
            cve_instance_affects_list,
            area,
            &mut self.affects_list_state,
        );

        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match action {
            Action::ScrollDown => {
                self.affects_list_state.select_next();
                Ok(None)
            }
            Action::ScrollUp => {
                self.affects_list_state.select_previous();
                Ok(None)
            }
            _ => Ok(Some(action)),
        }
    }
}

// TODO - find a more global place to put this if repeated
fn kernel_version_to_string(kernel_version: &KernelVersion) -> String {
    format!(
        "{}.{}{}",
        kernel_version.major,
        kernel_version.minor,
        if let Some(patch) = kernel_version.patch {
            format!(".{}", patch)
        } else {
            "".to_string()
        }
    )
}
