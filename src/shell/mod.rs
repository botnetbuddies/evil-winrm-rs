//! Interactive shell entry points and focused implementation modules.
mod assemblies;
mod completion;
mod dispatch;
mod editor;
mod menu;
mod output;
mod paths;
mod scripts;
mod terminal;
mod transfer_args;
pub use dispatch::execute_line;
pub use scripts::read_script;
pub use terminal::run;
#[cfg(test)]
mod tests;
