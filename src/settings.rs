use config::{Config, File};
use CFG_FILEPATHS;

fn load_defaults() -> Config {
    let mut settings = config::Config::new();
    settings
        .set_default("exit_on_error", false)
        .expect("Cannot set default value for exit_on_error setting");
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

pub(crate) fn parse_config() -> Config {
    let mut settings = load_defaults();
    for path in CFG_FILEPATHS.iter() {
        settings.merge(File::with_name("config.yaml")).unwrap();
    }
    // Change any single hosts not in CIDR notation to /32
    // let bind_ips: Vec<String> = settings.get("bind_ips").unwrap();
    // let mut mod_bind_ips: Vec<String> = ["".to_string()].to_vec();
    // for ip in bind_ips {
    // if ip.parse().is_err() {
    //     mod_bind_ips.append(format!("{}/32", ip));
    // }
    // else {
    //     mod_bind_ips.append(ip);
    // }
    // }
    // settings.set("bind_ips", mod_bind_ips);
    return settings;
}

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
