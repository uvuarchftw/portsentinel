use std::io::Read;
use std::process::exit;
use std::time::Duration;
use types::*;
use config::{Config, File, FileFormat};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::path::Path;
use CFG_FILEPATHS;

fn load_defaults() -> Config {
    // let app = AppConfig {
    //     bind_ips: [ "127.0.0.1".parse().unwrap() ].to_vec(),
    //     blacklist_hosts: [ "127.0.0.1".parse().unwrap() ].to_vec(),
    //     exit_on_error: true,
    //     print_config: true,
    //     file_logging: false,
    //     teams_logging: false,
    //     captured_text_newline_separator: ".".to_string(),
    //     screen_config: ScreenConfig {
    //         print_ascii: false,
    //         print_hex: false,
    //         print_disconnect: false,
    //     },
    //     file_logging_config: FileLoggingConfig {
    //         log_ascii: false,
    //         log_hex: false,
    //         log_disconnect: false,
    //     },
    //     teams_logging_config: TeamsLoggingConfig {
    //         channel_url: "".to_string(),
    //         log_ascii: false,
    //         log_hex: false,
    //         log_disconnect: false,
    //     },
    //     io_timeout: Duration::new(300, 0),
    //     ports: vec![],
    //     screen_logging: false
    // };
    //
    // return app;

    let mut settings = config::Config::new();
    settings.set_default("bind_ips","127.0.0.1").expect("Cannot set default value for bind_ips setting");
    settings.set_default("exit_on_error", false).expect("Cannot set default value for exit_on_error setting");
    settings.set_default("print_config", true).expect("Cannot set default value for print_config setting");
    settings.set_default("screen_logging", true).expect("Cannot set default value for screen_logging setting");
    settings.set_default("file_logging", true).expect("Cannot set default value for file_logging setting");
    settings.set_default("captured_text_newline_separator", ".").expect("Cannot set default value for captured_text_newline_separator setting");
    settings.set_default("io_timeout", 300).expect("Cannot set default value for io_timeout setting");
    return settings;
}

pub(crate) fn parse_config() -> Config {
    let mut settings = load_defaults();
    for path in CFG_FILEPATHS.iter() {
        settings.merge(File::with_name("config.yaml")).unwrap();
    }
    return settings;
}

// pub(crate) fn parse_config() -> AppConfig {
//     let mut app: AppConfig = load_defaults();
//     let mut config_str = String::new();
//     let mut file = match File::open("config.yaml") {
//         Ok(file) => file,
//         Err(e) => {
//             println!("Unable to open configuration file: {}", e.to_string());
//             exit(-1);
//         }
//     };
//
//     file.read_to_string(&mut config_str).unwrap();
//     let docs = YamlLoader::load_from_str(&config_str).unwrap();
//     let config = &docs[0];
//
//     if config["general"].is_badvalue() {
//         println!("No 'general' section found in configuration file");
//         exit(-1);
//     } else {
//         if !config["general"]["bind_ip"].is_badvalue() {
//             app.bind_ip = config["general"]["bind_ip"]
//                 .as_str()
//                 .expect("Invalid ['bind_ip'] value")
//                 .to_string();
//             println!("Binding to IP {}", app.bind_ip);
//         } else {
//             println!("No 'bind_ip' section found in configuration file");
//             app.bind_ip = String::from("0.0.0.0");
//             println!("Binding to default external IP {}", app.bind_ip);
//         }
//
//         if !config["general"]["file_logging"].is_badvalue() {
//             if config["general"]["file_logging"].as_bool().unwrap() {
//                 app.file_logging = true;
//                 println!("File Logging enabled");
//             } else {
//                 println!("File Logging disabled");
//             }
//         } else {
//             println!("Invalid ['file_logging'] value");
//             exit(-2);
//         }
//
//         if !config["general"]["teams_logging"].is_badvalue() {
//             if config["general"]["teams_logging"].as_bool().unwrap() {
//                 app.teams_logging = true;
//                 println!("Teams Logging enabled");
//             } else {
//                 println!("Teams Logging disabled");
//             }
//         } else {
//             println!("Invalid ['teams_logging'] value");
//             exit(-2);
//         }
//
//         if !config["general"]["captured_text_newline_seperator"].is_badvalue() {
//             app.captured_text_newline_seperator = config["general"]
//                 ["captured_text_newline_seperator"]
//                 .as_str()
//                 .unwrap()
//                 .parse()
//                 .unwrap();
//         } else {
//             app.captured_text_newline_seperator = ".".to_string();
//         }
//     }
//     if config["screen"].is_badvalue() {
//         println!("No 'screen' section found in configuration file");
//         exit(-1);
//     } else {
//         if !config["screen"]["print_ascii"].is_badvalue() {
//             if config["screen"]["print_ascii"].as_bool().unwrap() {
//                 app.screen_config.print_ascii = true;
//                 println!("Printing ASCII");
//             }
//         } else {
//             println!("Invalid ['print_ascii'] value");
//             exit(-2);
//         }
//
//         if !config["screen"]["print_hex"].is_badvalue() {
//             if config["screen"]["print_hex"].as_bool().unwrap() {
//                 app.screen_config.print_hex = true;
//                 println!("Printing hexadecimal");
//             }
//         } else {
//             println!("Invalid ['print_hex'] value");
//             exit(-2);
//         }
//
//         if !config["screen"]["print_disconnect"].is_badvalue() {
//             if config["screen"]["print_disconnect"].as_bool().unwrap() {
//                 app.screen_config.print_disconnect = true;
//                 println!("Printing connection times");
//             }
//         } else {
//             println!("Invalid ['print_disconnect'] value");
//             exit(-2);
//         }
//     }
//
//     if config["file_logging"].is_badvalue() {
//         println!("No 'file_logging' section found in configuration file");
//         exit(-1);
//     } else if config["general"]["file_logging"].as_bool().unwrap() {
//         if !config["file_logging"]["log_ascii"].is_badvalue() {
//             if config["file_logging"]["log_ascii"].as_bool().unwrap() {
//                 app.file_logging_config.log_ascii = true;
//                 println!("Logging ASCII to file");
//             }
//         } else {
//             println!("Invalid ['log_ascii'] value");
//             exit(-2);
//         }
//
//         if !config["file_logging"]["log_hex"].is_badvalue() {
//             if config["file_logging"]["log_hex"].as_bool().unwrap() {
//                 app.file_logging_config.log_hex = true;
//                 println!("Logging hexadecimal to file");
//             }
//         } else {
//             println!("Invalid ['log_hex'] value");
//             exit(-2);
//         }
//
//         if !config["file_logging"]["log_disconnect"].is_badvalue() {
//             if config["file_logging"]["log_disconnect"].as_bool().unwrap() {
//                 app.file_logging_config.log_disconnect = true;
//                 println!("Logging connection times to file");
//             }
//         } else {
//             println!("Invalid ['log_disconnect'] value");
//             exit(-2);
//         }
//     }
//
//     if config["teams"].is_badvalue() {
//         println!("No 'teams' section found in configuration file");
//         exit(-1);
//     } else if config["general"]["teams_logging"].as_bool().unwrap() {
//         if !config["teams"]["channel_url"].is_badvalue() {
//             if !config["teams"]["channel_url"].as_str().is_none() {
//                 app.teams_logging_config.channel_url = config["teams"]["channel_url"]
//                     .as_str()
//                     .unwrap()
//                     .parse()
//                     .unwrap();
//             } else {
//                 println!("Invalid ['channel_url'] value");
//                 exit(-2);
//             }
//         } else {
//             println!("Invalid ['channel_url'] value");
//             exit(-2);
//         }
//
//         if !config["teams"]["log_ascii"].is_badvalue() {
//             if config["teams"]["log_ascii"].as_bool().unwrap() {
//                 app.teams_logging_config.log_ascii = true;
//                 println!("Logging ASCII to Teams");
//             }
//         } else {
//             println!("Invalid ['log_ascii'] value");
//             exit(-2);
//         }
//
//         if !config["teams"]["log_hex"].is_badvalue() {
//             if config["teams"]["log_hex"].as_bool().unwrap() {
//                 app.teams_logging_config.log_hex = true;
//                 println!("Logging hexadecimal to Teams");
//             }
//         } else {
//             println!("Invalid ['log_hex'] value");
//             exit(-2);
//         }
//
//         if !config["teams"]["log_disconnect"].is_badvalue() {
//             if config["teams"]["log_disconnect"].as_bool().unwrap() {
//                 app.teams_logging_config.log_disconnect = true;
//                 println!("Logging disconnect times to Teams");
//             }
//         } else {
//             println!("Invalid ['log_disconnect'] value");
//             exit(-2);
//         }
//     }
//
//     println!("\nStarting listeners on the following ports:");
//     for port in config["ports"].as_vec().unwrap() {
//         let mut port_num: Option<u16> = None;
//         let port_type: TransportType;
//         let mut banner: Option<String> = None;
//         let mut nfqueue: Option<u16> = None;
//         let bind_ip = app.bind_ip.clone();
//         let io_timeout = app.io_timeout;
//
//         if !port["tcp"].is_badvalue() {
//             port_type = TransportType::Tcp;
//             match port["tcp"].as_i64() {
//                 None => {
//                     println!("Need a port number.");
//                     exit(-2);
//                 }
//                 Some(num) => {
//                     port_num = Some(num as u16);
//                     println!("TCP port {}", port_num.unwrap());
//                 }
//             }
//             match port["banner"].as_str() {
//                 None => {}
//                 Some(banner_msg) => {
//                     banner = Some(banner_msg.to_string());
//                     let banner_msg_mod = banner_msg
//                         .replace('\n', app.captured_text_newline_seperator.as_str())
//                         .replace('\r', app.captured_text_newline_seperator.as_str());
//                     println!("  with banner: {}", banner_msg_mod);
//                 }
//             }
//         } else if !port["udp"].is_badvalue() {
//             port_type = TransportType::Udp;
//             match port["udp"].as_i64() {
//                 None => {
//                     println!("Need a port number.");
//                     exit(-2);
//                 }
//                 Some(num) => {
//                     port_num = Some(num as u16);
//                     println!("UDP port {}", port_num.unwrap());
//                 }
//             }
//             match port["banner"].as_str() {
//                 None => {}
//                 Some(banner_msg) => {
//                     banner = Some(banner_msg.to_string());
//                     let banner_msg_mod = banner_msg
//                         .replace('\n', app.captured_text_newline_seperator.as_str())
//                         .replace('\r', app.captured_text_newline_seperator.as_str());
//                     println!("  with banner: {}", banner_msg_mod);
//                 }
//             }
//         } else if !port["icmp"].is_badvalue() {
//             port_type = TransportType::Icmp;
//             match port["icmp"].as_i64() {
//                 None => {}
//                 Some(_num) => {
//                     println!("ICMP does not use ports. Exiting.");
//                     exit(-2);
//                 }
//             }
//             match port["banner"].as_str() {
//                 None => {}
//                 Some(_banner_msg) => {
//                     println!("Cannot add banner to ICMP listener. Exiting.");
//                     exit(-2);
//                 }
//             }
//         } else {
//             println!("Invalid port specification in configuration file");
//             exit(-2);
//         }
//         match port["nfqueue"].as_i64() {
//             Some(queue) => {
//                 nfqueue = Some(queue as u16);
//                 println!("  Receiving packets from nfqueue {}", queue);
//                 println!("  Example iptables rule to make this work:");
//                 println!(
//                     "    iptables -A INPUT -p {} --dport {} -j NFQUEUE --queue-num {} --queue-bypass",
//                     port_type.to_string().to_lowercase(), port_num.unwrap(), queue
//                 );
//             }
//             None => {}
//         }
//
//         app.ports.insert(
//             0,
//             Port {
//                 port_num,
//                 port_type,
//                 banner,
//                 nfqueue,
//                 bind_ip,
//                 io_timeout,
//             },
//         )
//     }
//
//     return app;
// }
