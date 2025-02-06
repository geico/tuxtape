mod alert;
mod cve_edit_preview;

use crate::{action::Action, database::Cve, tui::components::Component};
pub use alert::Alert;
use color_eyre::Result;
pub use cve_edit_preview::CveEditPreview;
use ratatui::{prelude::*, widgets::*};
use serde::Deserialize;
use std::sync::Arc;
use strum::Display;

#[derive(Debug, Clone, PartialEq, Display, Deserialize)]
pub enum PopupType {
    Alert(String),
    CveEditPreview(Arc<Cve>),
}

/// The frame in which all Popups should be drawn
pub struct PopupFrame<'a> {
    frame: Block<'a>,
}

impl PopupFrame<'_> {
    fn new(header_text: String, fg_color: Option<Color>) -> Self {
        let fg_color = fg_color.unwrap_or(Color::White);

        let frame = Block::bordered()
            .title_top(Line::from(header_text).centered())
            .borders(Borders::ALL)
            .border_set(symbols::border::DOUBLE)
            .fg(fg_color);

        Self { frame }
    }

    /// Returns the area that the Popup content should be drawn in.
    fn get_content_area(&self, area: Rect) -> Rect {
        self.frame.inner(area)
    }
}

impl Component for PopupFrame<'_> {
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        frame.render_widget(Clear, area);
        frame.render_widget(&self.frame, area);

        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        Ok(Some(action))
    }
}
