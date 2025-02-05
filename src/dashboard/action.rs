use crate::database::DatabaseAction;
use crate::tui::pages::configs::ConfigsPageAction;
use crate::tui::pages::home::HomePageAction;
use crate::tui::pages::PageType;
use crate::tui::popups::PopupType;
use serde::Deserialize;
use strum::Display;

#[derive(Debug, Clone, PartialEq, Display, Deserialize)]
pub enum Action {
    Tick,
    Render,
    Resize(u16, u16),
    Suspend,
    Resume,
    Quit,
    ClearScreen,
    Error(String),
    Help,
    TabLeft,
    TabRight,
    PaneLeft,
    PaneRight,
    ScrollDown,
    ScrollUp,
    Select,
    ChangePage(PageType),
    Database(DatabaseAction),
    EditPatchAtPath(String),
    Popup(PopupType),
    HomePage(HomePageAction),
    ConfigsPage(ConfigsPageAction),
}
