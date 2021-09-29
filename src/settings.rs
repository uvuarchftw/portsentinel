use crate::types::AppConfig;
use crate::SETTINGS;
use config::File;
use config::{Config, ConfigError};
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use std::ops::RangeInclusive;
use std::time::Duration;

pub(crate) trait AppSettings {
    fn settings(&self) -> AppConfig;
    fn parse_settings(&self) -> Option<ConfigError>;
    fn check_source(&self, new_source: String) -> Option<ConfigError>;
    fn add_source(&mut self, new_source: String);
}

impl AppSettings for Config {
    /// Grab the AppConfig from the Config type
    fn settings<'e>(&self) -> AppConfig {
        let config = self
            .clone()
            .try_into::<'e, AppConfig>()
            .expect("Unable to parse settings");
        return config;
    }

    /// Check if the setting values are valid
    fn parse_settings<'e>(&self) -> Option<ConfigError> {
        return match self.clone().try_into::<'e, AppConfig>() {
            Ok(_) => {
                // Configuration is valid
                return None;
            }
            Err(err) => Some(err),
        };
    }

    /// Check if the settings source is valid
    fn check_source<'e>(&self, new_source: String) -> Option<ConfigError> {
        let config = match self.clone().merge(File::with_name(&new_source)) {
            Ok(_) => {
                return None;
            }
            Err(err) => Some(err),
        };
        return config;
    }

    /// Merge settings from new file source to existing settings
    fn add_source<'e>(&mut self, new_source: String) {
        let _ = self.merge(File::with_name(&new_source)).unwrap();
    }
}

/// Deserialize a duration of time from text
pub(crate) fn de_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let duration = u32::deserialize(deserializer)?;
    Ok(Duration::from_secs(duration as u64))
}

/// Deserialize a range from text
pub(crate) fn de_range<'de, D>(deserializer: D) -> Result<RangeInclusive<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let range_str = String::deserialize(deserializer)?;
    let range: Vec<u16> = range_str
        .split("..")
        .map(|x| {
            let result = x.parse::<u16>();
            match result {
                Ok(x) => x,
                Err(_) => 0,
            }
        })
        .collect();

    if range[0] == 0 || range[1] == 0 {
        eprintln!("Invalid characters in port range specified ({})", range_str);
        return Err(D::Error::custom("Bad characters in port range"));
    } else if range.len() != 2 || range[0] > range[1] {
        eprintln!("Invalid port range specified ({}..{})", range[0], range[1]);
        return Err(D::Error::custom("Bad port range"));
    }
    Ok(range[0]..=range[1])
}

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

/// Show the current AppConfig settings
pub(crate) fn show() {
    let settings = SETTINGS.read().unwrap().settings();
    println!(" * Settings :: \n\x1b[31m{:#?}\x1b[0m", settings);
}
