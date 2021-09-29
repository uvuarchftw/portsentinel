use crate::types::AppSettings;
use crate::SETTINGS;
use config::Config;

/// Set default values for some settings
pub(crate) fn load_defaults() -> Config {
    let mut settings = config::Config::new();
    settings
        .set_default("print_config", true)
        .expect("Cannot set default value for print_config setting");
    settings
        .set_default("screen_logging", true)
        .expect("Cannot set default value for screen_logging setting");
    settings
        .set_default("file_logging", true)
        .expect("Cannot set default value for file_logging setting");
    settings
        .set_default("captured_text_newline_separator", ".")
        .expect("Cannot set default value for captured_text_newline_separator setting");
    settings
        .set_default("io_timeout_seconds", 300)
        .expect("Cannot set default value for io_timeout setting");
    return settings;
}

pub(crate) fn show() {
    let settings = SETTINGS.read().unwrap().settings();
    println!(" * Settings :: \n\x1b[31m{:#?}\x1b[0m", settings);
}
