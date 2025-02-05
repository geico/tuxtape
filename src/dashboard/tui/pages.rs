use crate::{action::Action, config::Config, tui::components::*};
use color_eyre::Result;
use configs::ConfigsPage;
use home::HomePage;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, hash::Hash, sync::Arc};
use strum::{Display, EnumCount, EnumIter, FromRepr};
use tokio::sync::mpsc::UnboundedSender;

pub mod configs;
pub mod home;

#[derive(
    Default,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Display,
    FromRepr,
    EnumIter,
    EnumCount,
    Serialize,
    Deserialize,
)]
pub enum PageType {
    #[default]
    #[strum(to_string = "Home")]
    Home,
    #[strum(to_string = "Configs")]
    Configs,
}

pub struct PageManager {
    pages: HashMap<PageType, Box<dyn Component>>,
    current_page: PageType,
}

impl PageManager {
    pub fn new(config: Arc<Config>) -> Self {
        let mut pages: HashMap<PageType, Box<dyn Component>> = HashMap::new();
        pages.insert(PageType::Home, Box::new(HomePage::new(config)));
        pages.insert(PageType::Configs, Box::new(ConfigsPage::new()));

        Self {
            pages,
            current_page: PageType::Home,
        }
    }

    pub fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match action {
            Action::ChangePage(page_type) => self.current_page = page_type,
            _ => return self.get_current_page().update(action),
        }

        Ok(Some(action))
    }

    pub fn get_current_page(&mut self) -> &mut Box<dyn Component> {
        self.pages
            .get_mut(&self.current_page)
            .expect("Attempted to get a Page that isn't registered")
    }

    pub fn register_action_handler(&mut self, tx: UnboundedSender<Action>) {
        for (_, page) in self.pages.iter_mut() {
            page.register_action_handler(tx.clone())
                .expect("Registering page should never fail");
        }
    }
}
