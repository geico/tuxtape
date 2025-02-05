/// A generic popup used for alerting the user without panicking.
use super::PopupFrame;
use crate::{action::Action, tui::components::Component};
use color_eyre::Result;
use ratatui::{prelude::*, widgets::*};

pub struct Alert<'a> {
    frame: PopupFrame<'a>,
    text: Paragraph<'a>,
}

impl Alert<'_> {
    pub fn new(text: String) -> Self {
        let frame = PopupFrame::new("Alert".to_string(), Some(Color::Red));
        let text = Paragraph::new(text).centered();

        Self { frame, text }
    }
}

impl Component for Alert<'_> {
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        self.frame.draw(frame, area)?;
        frame.render_widget(&self.text, self.frame.get_content_area(area));

        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        // Consume navigation actions, pass through all else
        match action {
            Action::ScrollDown | Action::ScrollUp | Action::TabLeft | Action::TabRight => Ok(None),
            _ => Ok(Some(action)),
        }
    }
}
