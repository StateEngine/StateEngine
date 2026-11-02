//! Native CLI routing. Startup is called at process entry, before Bootstrap
//! reads configuration and before a worker or store is opened.
#[path = "route/admit.rs"]
mod admit;
#[cfg(any(target_os = "linux", windows))]
#[path = "route/autostart.rs"]
mod autostart;
#[path = "route/credential.rs"]
pub mod credential;
#[path = "route/direct.rs"]
pub mod direct;
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
#[path = "route/runtime.rs"]
mod runtime_control;
#[path = "route/select.rs"]
mod select;
#[path = "route/setup.rs"]
pub mod setup;
#[path = "route/status.rs"]
mod status;
#[path = "route/uninstall.rs"]
pub mod uninstall;
