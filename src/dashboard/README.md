# tuxtape-dashboard

A TUI dashboard for creating, reviewing, and submitting kpatch-compatible livepatches.

## Design

This project is based on the [`ratatui` Component template](https://ratatui.rs/templates/component/), but has some modifications to make the solution more domain specific and easier to maintain based on the needs of this project. Before contributing to this project, I suggest reading through the linked documentation as it breaks down most of the project structure of this program. The following documentation in this README is mostly meant to supplement that documentation and explain the changes made to that template.

### Component

A `Component` is an object that can be rendered onto the terminal (or to use `ratatui` lingo, `Frame`, which refers to the visible portion in your terminal emulator). 

> Note: the term `Widget` is used in the `ratatui` ecosystem to refer to something similar. For our purposes in this project, just consider a `Widget` to be a `Component` designed by the `ratatui` community.

### Page

A "Page" is a term which is specific to this project. It refers to a collection of `Component`s that work together to create something akin to a webpage. For example, the `HomePage` consists of the table of CVEs that the user utilizes to select CVEs they wish to edit.

### Background

Also specific to this project, the `Background` is the "anchor point" that all Pages are rendered onto. The `Background` should _always_ be rendered, so it's treated specially here.

The `Background` visually consists of three things:

1. `PageTabs` (used to navigate between the different Pages)
2. `PageManager::current_page` (the main thing the user is looking at and operating on)
3. `Footer` (used to display keybindings)

The `Background` is the parent of `PageManager` which instantiates all the Pages and forwards `draw()` calls to the current Page.

### Popup

A `Popup` is a special kind of component that takes priority over everything. When a `Popup` is displayed, it intercepts all `Actions` that would be consumed by either the `Background` or current Page. It gets rendered on top of the Page as well.

## Message passing

We should avoid blocking for long times on the TUI thread as it will make the program feel unresponsive. To get around this, we use a message passing scheme. The root `Action` enum is located at `action.rs` and this represents any action that can occur in the program, be that a tick, call to render, an event from the terminal resizing, the user wishing to quit, a request to query the database, etc. When a module in the program has an `Action` that is specific to itself (e.g. `DatabaseAction`), it gets declared in that module (`database.rs::DatabaseAction`) and wrapped in a global `Action` in `actions.rs` (e.g. `Database(DatabaseAction)`). 

In the Components boilerplate, `KeyEvent`s (the user pressing a key) are interpereted into `Action`s in `App::handle_events()`. The `Action`s are received by `App::handle_actions()` and get sent "downstream" to things that can consume them. The stream looks as follows:

```
App -> 
    Background -> 
        (if exists) Popup -> 
        PageTabs -> 
        PageManager -> 
            PageManager[current_page] -> 
Database (if DatabaseAction)
```

When writing a consumer of `Action`s, it should either fully consume an `Action` in its `update()`, change some of its own state based on the `Action` and forward the `Action` downstream, or ignore the `Action` entirely and forward it downstream. **Always** make sure that you are not fully consuming `Action`s that your `Component` doesn't need or that other `Component`s expect as they may be downstream from your consumer.

For example, `HomePage::update()` may look like this:

```
fn update(&mut self, action: Action) -> Result<Option<Action>> {
    match &action {
        Action::ScrollDown => self.table_state.scroll_down_by(1),
        Action::ScrollUp => self.table_state.scroll_up_by(1),
        Action::Database(DatabaseAction::Response(response)) => match response {
            Response::PopulateTable(cve_instances) => self.build_table(cve_instances.clone()),
        },
        Action::Select => self.edit_patch()?,
        _ => return Ok(Some(action)),
    }
    Ok(None)
}
```

It cares about only four types of `Action`s: `ScrollDown`/`ScrollUp`/`Select` (used for navigation) and `Database(DatabaseAction::Response(PopulateTable))` (sent by `Database` after `HomePage` requests the information it needs to draw its table). The only time it returns `Ok(None)` is when it has fully consumed the action (since `HomePage` is the only thing in the stream that consumes for those four `Actions`, it doesn't need to forward them on). If it receives an `Action` it *doesn't* consume, the `_ => return Ok(Some(action))` case gets hit and the `Action` is forwarded down the stream.

Every `Component` should have a member `command_tx: Option<UnboundedSender<Action>>` (it's an `Option` because the Components template registers all of the `command_tx` after the TUI is fully running, which I'm not sure is entirely necessary and may remove later). When an `Action` needs to be emitted by a `Component` (e.g. `HomePage` emitting an `Action::Database(DatabaseAction::Request))`), it should be sent via `self.command_tx.send()`. There is a single listener for the commands in `App` that will push all `Action`s emitted since the previous loop downstream in the main loop at `App::run()`.
