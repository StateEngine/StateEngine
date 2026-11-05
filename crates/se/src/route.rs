//! Native CLI routing. Startup is called at process entry, before Bootstrap
//! reads configuration and before a worker or store is opened.
#[path = "route/admit.rs"]
mod admit;
#[cfg(any(target_os = "linux", windows))]
#[path = "route/autostart.rs"]
mod autostart;
#[path = "route/clock.rs"]
mod clock;
#[path = "route/credential.rs"]
pub mod credential;
#[path = "route/direct.rs"]
pub mod direct;
mod doctor;
#[path = "route/empty_home.rs"]
mod empty_home;
mod endpoint_diagnostic;
#[path = "route/execute.rs"]
pub mod execute;
#[path = "route/files.rs"]
pub mod files;
#[path = "route/hook.rs"]
mod hook;
#[path = "route/hosted.rs"]
mod hosted;
#[path = "route/identity.rs"]
pub mod identity;
#[path = "route/init.rs"]
mod init;
#[path = "route/init_config.rs"]
mod init_config;
#[path = "route/owner.rs"]
pub mod owner;
#[path = "route/process.rs"]
mod process;
#[path = "route/remove.rs"]
mod remove;
mod retained;
#[path = "route/runtime.rs"]
mod runtime_control;
#[path = "route/select.rs"]
mod select;
mod session_observation;
#[path = "route/setup.rs"]
pub mod setup;
#[path = "route/status.rs"]
mod status;
#[path = "route/uninstall.rs"]
pub mod uninstall;

#[cfg(any(target_os = "linux", windows))]
pub use runtime_control::foreground;

#[path = "route/command_hint.rs"]
mod command_hint;
