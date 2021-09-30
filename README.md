# PortSentinel
#### Port listener with logging and alerts

## Features:
 - IPv4 and IPv6 support
 - Plain TCP/UDP listeners
 - Raw packet listener (via NFQueue)
 - Live configuration file refresh
 - Logging to screen, file, and Teams
 - Able to specify a range of ports to listen on
 - Able to specify a banner for TCP/UDP listeners
 - Able to filter/blacklist hosts from logging and alerts

## Installation
Dependencies:
 - libnetfilter-queue-dev

Build Binary:
```
git clone https://github.com/uvuarchftw/portsentinel/
cd portsentinel
cargo build --release
target/release/portsentinel
```

## Usage

The configuration file can currently live in only 4 locations:
- /etc/portsentinel/config.yaml
- /etc/portsentinel/config.yml
- ./config.yaml
- ./config.yml

## Configuration

| Parameter                  | Description                                     | Default                                                    |
| -----------------------    | ---------------------------------------------   | ---------------------------------------------------------- |
| `blacklist_hosts` | A list of IP addresses that are to be filtered out from logging and alerts |  |
| `captured_text_newline_separator` | When printing/logging ASCII text, \n and \r are converted to the seperator listed here | "." |
| `io_timeout_seconds` | Number of seconds before a connection times out | 300 |
| `print_config` | Print the configuration the application uses | true |
| `screen_logging` | Log results to the screen | true |
| `file_logging` | Log results to a file | true |
| `teams_logging` | Log results to Teams via webhook |  |
| `screen.print_ascii` | Print decoded ASCII from packet data to the screen |  |
| `screen.print_hex` | Print hex encoded packet data to the screen |  |
| `screen.print_disconnect` | Print disconnect from TCP listener |  |
| `file.log_filepath` | File path for logging results |  |
| `file.log_ascii` | Log decoded ASCII from packet data to the file |  |
| `file.log_hex` | Log hex encoded packet data to the file |  |
| `file.log_disconnect` | Log disconnect from TCP listener |  |
| `teams.channel_url` | URL for Teams channel webhook |  |
| `teams.log_ascii` | Log decoded ASCII from packet data to Teams |  |
| `teams.log_hex` | Log hex encoded packet data to Teams |  |
| `teams.log_disconnect` | Log disconnect from TCP listener to Teams |  |
| `ports` | A list of the different port listeners |  |
| `ports.*.port_type` | Type of protocol to listen for: TCP, UDP, ICMP |  |
| `ports.*.port_range` | Range of port(s) to listen for |  |
| `ports.*.banner` | The banner to send to a client. Note: This cannot be specified when also using a NFQueue for a port specification |  |
| `ports.*.bind_ip` | The IP address to listen on |  |
| `ports.*.io_timeout` | Number of seconds to wait before connection times out. Overrides global `io_timeout_seconds` |  |
| `ports.*.nfqueue` | Set port listener to bind to NFQueue. Note: Using this requires the program to be run as root to successfully bind to NFQueues |  |
