use crate::tui::components::*;
use crate::{
    action::Action, app::Mode, config::Config, tui::pages::*, tui::popups, tui::popups::PopupType,
};
use color_eyre::{eyre::eyre, Result};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    prelude::*,
    style::{Color, Stylize},
    widgets::*,
};
use std::collections::HashMap;
use std::sync::Arc;
use strum::{EnumCount, IntoEnumIterator};
use tokio::sync::mpsc::UnboundedSender;

/// The root from which all other `Page`s will be mounted.
/// The background will run at all times.
pub struct Background {
    command_tx: Option<UnboundedSender<Action>>,
    tabs: PageTabs,
    page_manager: PageManager,
    footer: Footer,
    popup: Option<Box<dyn Component>>,
}

impl Background {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        Ok(Self {
            command_tx: None,
            tabs: PageTabs::default(),
            page_manager: PageManager::new(config.clone()),
            footer: Footer::new(config),
            popup: None,
        })
    }

    fn display_popup(&mut self, popup_type: PopupType) -> Result<()> {
        match popup_type {
            PopupType::Alert(alert_text) => {
                self.popup = Some(Box::new(popups::Alert::new(alert_text)));
            }
            PopupType::CveEditPreview(cve_instance) => {
                let command_tx = match self.command_tx.as_ref() {
                    Some(command_tx) => command_tx,
                    None => {
                        return Err(eyre!(
                            "self.command_tx should always exist by the time this is called"
                        ))
                    }
                };

                self.popup = Some(Box::new(popups::CveEditPreview::new(
                    cve_instance,
                    command_tx.clone(),
                )));
            }
        }

        Ok(())
    }
}

impl Component for Background {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.command_tx = Some(tx.clone());
        self.page_manager.register_action_handler(tx.clone());
        self.tabs.register_action_handler(tx)
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        // If there is a Popup, let it be the first consumer of events.
        let maybe_unconsumed_action = match &mut self.popup {
            // If there is a Popup, check first if the user is trying to close it before forwarding the action into the Popup
            Some(popup) => match action {
                Action::Quit => {
                    self.popup = None;
                    // Consume the Quit event
                    None
                }
                _ => popup.update(action)?,
            },
            None => Some(action),
        };
        let unconsumed_action = match maybe_unconsumed_action {
            Some(action) => action,
            None => return Ok(None),
        };

        let unconsumed_action = match self.tabs.update(unconsumed_action)? {
            Some(action) => action,
            None => return Ok(None),
        };

        let unconsumed_action = match self.page_manager.update(unconsumed_action)? {
            Some(action) => action,
            None => return Ok(None),
        };

        // Consume Background-specific actions here
        match unconsumed_action {
            Action::Popup(popup_type) => {
                self.display_popup(popup_type)?;
                Ok(None)
            }
            _ => Ok(Some(unconsumed_action)),
        }
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(2),
                Constraint::Percentage(98),
                Constraint::Percentage(2),
            ])
            .split(area);

        self.tabs.draw(frame, chunks[0])?;
        self.page_manager
            .get_current_page()
            .draw(frame, chunks[1])?;
        self.footer.draw(frame, chunks[2])?;

        if let Some(popup) = &mut self.popup {
            let popup_area = chunks[1].inner(Margin::new(1, 1));

            if let Err(err) = popup.draw(frame, popup_area) {
                if let Some(command_tx) = &mut self.command_tx {
                    let _ = command_tx.send(Action::Error(format!("Failed to draw: {:?}", err)));
                }
            }
        }

        Ok(())
    }
}

// Implement extra functionality to Page enum for use in PageTabs.
impl PageType {
    /// Get the next tab. If there is no next tab, loop around to first tab.
    fn next(self) -> Self {
        let current_index = self as usize;
        const MAX_PAGE_INDEX: usize = PageType::COUNT - 1;
        let next_index = match current_index {
            MAX_PAGE_INDEX => 0,
            _ => current_index + 1,
        };
        Self::from_repr(next_index).unwrap_or(self)
    }

    /// Get the previous tab. If there is no previous tab, loop around to last tab.
    fn previous(self) -> Self {
        let current_index = self as usize;
        let previous_index = match current_index {
            0 => PageType::COUNT - 1,
            _ => current_index - 1,
        };
        Self::from_repr(previous_index).unwrap_or(self)
    }

    /// Return tab's name as a styled `Line`
    fn title(self) -> Line<'static> {
        format!("  {self}  ")
            .fg(Color::White)
            .bg(Color::DarkGray)
            .into()
    }
}

#[derive(Default)]
struct PageTabs {
    command_tx: Option<UnboundedSender<Action>>,
    selected_tab: PageType,
}

impl Component for PageTabs {
    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match action {
            Action::TabLeft => {
                self.selected_tab = self.selected_tab.previous();
                Ok(Some(Action::ChangePage(self.selected_tab)))
            }
            Action::TabRight => {
                self.selected_tab = self.selected_tab.next();
                Ok(Some(Action::ChangePage(self.selected_tab)))
            }
            _ => Ok(Some(action)),
        }
    }

    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.command_tx = Some(tx.clone());
        Ok(())
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        let titles = PageType::iter().map(PageType::title);
        let highlight_style = (Color::White, Color::Green);
        let selected_tab_index = self.selected_tab as usize;
        Tabs::new(titles)
            .highlight_style(highlight_style)
            .select(selected_tab_index)
            .padding("", "")
            .divider(" ")
            .render(area, frame.buffer_mut());

        Ok(())
    }
}

struct Footer {
    text: String,
}

impl Footer {
    fn new(config: Arc<Config>) -> Self {
        let keybindings = config
            .keybindings
            .0
            .get(&Mode::Normal)
            .expect("Program should have panicked by now if config didn't exist");

        let tab_left_keys = Footer::find_keycodes_for_action(keybindings, &Action::TabLeft);
        let tab_right_keys = Footer::find_keycodes_for_action(keybindings, &Action::TabRight);
        let pane_left_keys = Footer::find_keycodes_for_action(keybindings, &Action::PaneLeft);
        let pane_right_keys = Footer::find_keycodes_for_action(keybindings, &Action::PaneRight);
        let scroll_down_keys = Footer::find_keycodes_for_action(keybindings, &Action::ScrollDown);
        let scroll_up_keys = Footer::find_keycodes_for_action(keybindings, &Action::ScrollUp);
        let select_keys = Footer::find_keycodes_for_action(keybindings, &Action::Select);
        let quit_keys = Footer::find_keycodes_for_action(keybindings, &Action::Quit);

        let text = format!(
            "[Pane ←/→: {}/{}] [Tab ←/→: {}/{}] [Scroll ↑/↓: {}/{}] [Select: {}] [Quit: {}]",
            Footer::keycodes_to_display_text(pane_left_keys),
            Footer::keycodes_to_display_text(pane_right_keys),
            Footer::keycodes_to_display_text(tab_left_keys),
            Footer::keycodes_to_display_text(tab_right_keys),
            Footer::keycodes_to_display_text(scroll_up_keys),
            Footer::keycodes_to_display_text(scroll_down_keys),
            Footer::keycodes_to_display_text(select_keys),
            Footer::keycodes_to_display_text(quit_keys)
        );

        Self { text }
    }

    /// Return the `KeyCode`(s) (plural if a key combo is used) that map to an `Action`
    fn find_keycodes_for_action(
        map: &HashMap<Vec<KeyEvent>, Action>,
        value: &Action,
    ) -> Vec<KeyCode> {
        let vec: Option<Vec<KeyCode>> = map.iter().find_map(|(key, val)| {
            if val == value {
                Some(key.iter().map(|key| key.code).collect())
            } else {
                None
            }
        });

        vec.unwrap_or_default()
    }

    /// Return a String of displayable text for all `KeyCode`(s) in the vec.
    fn keycodes_to_display_text(keycodes: Vec<KeyCode>) -> String {
        let mut retval = String::new();
        for (i, keycode) in keycodes.iter().enumerate() {
            if i > 0 {
                retval.push('+');
            }
            retval.push_str(keycode.to_string().as_str());
        }

        retval
    }
}

impl Component for Footer {
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        frame.render_widget(Paragraph::new(self.text.clone()).centered(), area);

        Ok(())
    }
}
