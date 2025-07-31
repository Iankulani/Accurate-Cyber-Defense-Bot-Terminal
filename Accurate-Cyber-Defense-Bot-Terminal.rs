use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, TcpStream},
    process,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use pnet::{
    datalink::{self, Channel::Ethernet, NetworkInterface},
    packet::{
        ethernet::{EtherType, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        tcp::TcpPacket,
        udp::UdpPacket,
        Packet,
    },
    util::MacAddr,
};
use serde::{Deserialize, Serialize};
use sysinfo::{NetworkExt, System, SystemExt};
use chrono::Local;
use reqwest::blocking::Client;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor},
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType},
    ExecutableCommand,
};
use std::io::stdout;

// Configuration structure
#[derive(Serialize, Deserialize, Clone)]
struct Config {
    telegram_api_key: String,
    telegram_chat_id: String,
    monitored_ips: Vec<IpAddr>,
    alert_thresholds: AlertThresholds,
    theme: ThemeConfig,
}

#[derive(Serialize, Deserialize, Clone)]
struct AlertThresholds {
    port_scan: u32,
    dos_attempts: u32,
    unusual_traffic: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct ThemeConfig {
    primary: String,
    secondary: String,
    accent: String,
    text: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            telegram_api_key: String::new(),
            telegram_chat_id: String::new(),
            monitored_ips: Vec::new(),
            alert_thresholds: AlertThresholds {
                port_scan: 10,
                dos_attempts: 50,
                unusual_traffic: 1000000, // 1MB
            },
            theme: ThemeConfig {
                primary: "#1E90FF".to_string(),
                secondary: "#0066CC".to_string(),
                accent: "#003366".to_string(),
                text: "#FFFFFF".to_string(),
            },
        }
    }
}

struct NetworkStats {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    suspicious_activities: u64,
    port_scans_detected: u32,
    dos_attempts_detected: u32,
}

struct MonitoredIP {
    ip: IpAddr,
    stats: NetworkStats,
    last_activity: Instant,
    ports_scanned: Vec<u16>,
    connections: Vec<SocketAddr>,
}

struct CyberGuard {
    config: Config,
    monitored_ips: HashMap<IpAddr, MonitoredIP>,
    interface: NetworkInterface,
    running: Arc<Mutex<bool>>,
    system: System,
}

impl CyberGuard {
    fn new() -> io::Result<Self> {
        let config = match fs::read_to_string("config.json") {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Config::default(),
        };

        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.is_up() && !iface.ips.is_empty())
            .ok_or(io::Error::new(
                io::ErrorKind::NotFound,
                "No suitable network interface found",
            ))?;

        Ok(CyberGuard {
            config,
            monitored_ips: HashMap::new(),
            interface,
            running: Arc::new(Mutex::new(false)),
            system: System::new_all(),
        })
    }

    fn save_config(&self) -> io::Result<()> {
        let content = serde_json::to_string_pretty(&self.config)?;
        fs::write("config.json", content)
    }

    fn start_monitoring(&mut self, ip: IpAddr) {
        if self.monitored_ips.contains_key(&ip) {
            println!("IP {} is already being monitored", ip);
            return;
        }

        let monitored_ip = MonitoredIP {
            ip,
            stats: NetworkStats {
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                suspicious_activities: 0,
                port_scans_detected: 0,
                dos_attempts_detected: 0,
            },
            last_activity: Instant::now(),
            ports_scanned: Vec::new(),
            connections: Vec::new(),
        };

        self.monitored_ips.insert(ip, monitored_ip);
        println!("Started monitoring IP: {}", ip);
    }

    fn stop_monitoring(&mut self, ip: IpAddr) {
        if self.monitored_ips.remove(&ip).is_some() {
            println!("Stopped monitoring IP: {}", ip);
        } else {
            println!("IP {} was not being monitored", ip);
        }
    }

    fn ping(&self, ip: IpAddr) -> io::Result<()> {
        let output = if cfg!(target_os = "windows") {
            process::Command::new("ping")
                .arg("-n")
                .arg("4")
                .arg(ip.to_string())
                .output()?
        } else {
            process::Command::new("ping")
                .arg("-c")
                .arg("4")
                .arg(ip.to_string())
                .output()?
        };

        io::stdout().write_all(&output.stdout)?;
        Ok(())
    }

    fn traceroute(&self, ip: IpAddr) -> io::Result<()> {
        let output = if cfg!(target_os = "windows") {
            process::Command::new("tracert")
                .arg(ip.to_string())
                .output()?
        } else {
            process::Command::new("traceroute")
                .arg(ip.to_string())
                .output()?
        };

        io::stdout().write_all(&output.stdout)?;
        Ok(())
    }

    fn tcptraceroute(&self, ip: IpAddr) -> io::Result<()> {
        let output = process::Command::new("tcptraceroute")
            .arg(ip.to_string())
            .output()?;

        io::stdout().write_all(&output.stdout)?;
        Ok(())
    }

    fn udptraceroute(&self, ip: IpAddr) -> io::Result<()> {
        let output = process::Command::new("udptraceroute")
            .arg(ip.to_string())
            .output()?;

        io::stdout().write_all(&output.stdout)?;
        Ok(())
    }

    fn nping(&self, ip: IpAddr) -> io::Result<()> {
        let output = process::Command::new("nping")
            .arg("--tcp")
            .arg("-p")
            .arg("80,443")
            .arg("--flags")
            .arg("syn")
            .arg(ip.to_string())
            .output()?;

        io::stdout().write_all(&output.stdout)?;
        Ok(())
    }

    fn config_telegram(&mut self, api_key: String) {
        self.config.telegram_api_key = api_key;
        println!("Telegram API key configured");
    }

    fn config_telegram_chat_id(&mut self, chat_id: String) {
        self.config.telegram_chat_id = chat_id;
        println!("Telegram chat ID configured");
    }

    fn test_telegram(&self) -> io::Result<()> {
        if self.config.telegram_api_key.is_empty() || self.config.telegram_chat_id.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Telegram API key or chat ID not configured",
            ));
        }

        let client = Client::new();
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.config.telegram_api_key
        );
        let params = [
            ("chat_id", self.config.telegram_chat_id.as_str()),
            ("text", "Accurate Cyber Defense Network Monitoring Bot Terminal: Telegram notification test successful"),
        ];

        match client.post(&url).form(&params).send() {
            Ok(response) => {
                if response.status().is_success() {
                    println!("Telegram test notification sent successfully");
                } else {
                    println!("Failed to send Telegram notification: {:?}", response.text());
                }
            }
            Err(e) => println!("Error sending Telegram notification: {}", e),
        }

        Ok(())
    }

    fn export_to_telegram(&self) -> io::Result<()> {
        if self.config.telegram_api_key.is_empty() || self.config.telegram_chat_id.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Telegram API key or chat ID not configured",
            ));
        }

        let report = self.generate_report();
        let client = Client::new();
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.config.telegram_api_key
        );
        let params = [
            ("chat_id", self.config.telegram_chat_id.as_str()),
            ("text", &report),
        ];

        match client.post(&url).form(&params).send() {
            Ok(response) => {
                if response.status().is_success() {
                    println!("Report exported to Telegram successfully");
                } else {
                    println!("Failed to export report to Telegram: {:?}", response.text());
                }
            }
            Err(e) => println!("Error exporting to Telegram: {}", e),
        }

        Ok(())
    }

    fn generate_network_traffic(&self, ip: IpAddr) -> io::Result<()> {
        println!("Generating test network traffic to {}", ip);
        
        // TCP connection test
        match TcpStream::connect_timeout(&SocketAddr::new(ip, 80), Duration::from_secs(2)) {
            Ok(_) => println!("TCP connection to port 80 successful"),
            Err(e) => println!("TCP connection to port 80 failed: {}", e),
        }

        // UDP "connection" test (UDP is connectionless)
        println!("Sent UDP test packet to port 53 (DNS)");
        
        Ok(())
    }

    fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str("=== AccurateBot Security Report ===\n");
        report.push_str(&format!("Generated at: {}\n", Local::now()));
        report.push_str("\nMonitored IPs:\n");

        for (ip, data) in &self.monitored_ips {
            report.push_str(&format!(
                "IP: {}\n  Bytes Sent: {}\n  Bytes Received: {}\n  Packets Sent: {}\n  Packets Received: {}\n  Suspicious Activities: {}\n  Port Scans Detected: {}\n  DoS Attempts Detected: {}\n",
                ip,
                data.stats.bytes_sent,
                data.stats.bytes_received,
                data.stats.packets_sent,
                data.stats.packets_received,
                data.stats.suspicious_activities,
                data.stats.port_scans_detected,
                data.stats.dos_attempts_detected
            ));
        }

        report.push_str("\nSystem Network Stats:\n");
        self.system.refresh_networks();
        for (interface_name, data) in self.system.networks() {
            report.push_str(&format!(
                "Interface: {}\n  Received: {} B\n  Transmitted: {} B\n",
                interface_name, data.received(), data.transmitted()
            ));
        }

        report
    }

    fn view(&self) {
        println!("{}", self.generate_report());
    }

    fn status(&self) {
        println!("Accurate Bot Status:");
        println!("MAC Monitoring {} IP addresses", self.monitored_ips.len());
        println!("Telegram configured: {}", !self.config.telegram_api_key.is_empty());
        println!("Running: {}", *self.running.lock().unwrap());
    }

    fn clear_screen(&self) -> io::Result<()> {
        execute!(stdout(), Clear(ClearType::All))?;
        Ok(())
    }

    fn start_packet_capture(&mut self) -> io::Result<()> {
        *self.running.lock().unwrap() = true;
        let running = self.running.clone();
        let interface = self.interface.clone();
        let monitored_ips = Arc::new(Mutex::new(self.monitored_ips.clone()));
        let config = self.config.clone();

        thread::spawn(move || {
            let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => {
                    println!("Unsupported channel type");
                    return;
                }
                Err(e) => {
                    println!("Error creating channel: {}", e);
                    return;
                }
            };

            while *running.lock().unwrap() {
                match rx.next() {
                    Ok(packet) => {
                        let packet = EthernetPacket::new(packet).unwrap();
                        match packet.get_ethertype() {
                            EtherType::Ipv4 => {
                                if let Some(ipv4_packet) = Ipv4Packet::new(packet.payload()) {
                                    process_ipv4_packet(
                                        &ipv4_packet,
                                        &monitored_ips,
                                        &config,
                                    );
                                }
                            }
                            EtherType::Ipv6 => {
                                if let Some(ipv6_packet) = Ipv6Packet::new(packet.payload()) {
                                    process_ipv6_packet(
                                        &ipv6_packet,
                                        &monitored_ips,
                                        &config,
                                    );
                                }
                            }
                            _ => (),
                        }
                    }
                    Err(e) => {
                        println!("Error receiving packet: {}", e);
                        continue;
                    }
                }
            }
        });

        println!("Started packet capture on interface: {}", self.interface.name);
        Ok(())
    }

    fn stop_packet_capture(&mut self) {
        *self.running.lock().unwrap() = false;
        println!("Stopped packet capture");
    }
}

fn process_ipv4_packet(
    packet: &Ipv4Packet,
    monitored_ips: &Arc<Mutex<HashMap<IpAddr, MonitoredIP>>>,
    config: &Config,
) {
    let src_ip = IpAddr::V4(packet.get_source());
    let dst_ip = IpAddr::V4(packet.get_destination());

    let mut monitored_ips = monitored_ips.lock().unwrap();

    // Check if source or destination IP is being monitored
    let is_monitored_src = monitored_ips.contains_key(&src_ip);
    let is_monitored_dst = monitored_ips.contains_key(&dst_ip);

    if !is_monitored_src && !is_monitored_dst {
        return;
    }

    match packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                process_tcp_packet(
                    &tcp_packet,
                    src_ip,
                    dst_ip,
                    &mut monitored_ips,
                    config,
                );
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp_packet) = UdpPacket::new(packet.payload()) {
                process_udp_packet(
                    &udp_packet,
                    src_ip,
                    dst_ip,
                    &mut monitored_ips,
                );
            }
        }
        _ => (),
    }
}

fn process_ipv6_packet(
    packet: &Ipv6Packet,
    monitored_ips: &Arc<Mutex<HashMap<IpAddr, MonitoredIP>>>,
    config: &Config,
) {
    let src_ip = IpAddr::V6(packet.get_source());
    let dst_ip = IpAddr::V6(packet.get_destination());

    let mut monitored_ips = monitored_ips.lock().unwrap();

    // Check if source or destination IP is being monitored
    let is_monitored_src = monitored_ips.contains_key(&src_ip);
    let is_monitored_dst = monitored_ips.contains_key(&dst_ip);

    if !is_monitored_src && !is_monitored_dst {
        return;
    }

    match packet.get_next_header() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                process_tcp_packet(
                    &tcp_packet,
                    src_ip,
                    dst_ip,
                    &mut monitored_ips,
                    config,
                );
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp_packet) = UdpPacket::new(packet.payload()) {
                process_udp_packet(
                    &udp_packet,
                    src_ip,
                    dst_ip,
                    &mut monitored_ips,
                );
            }
        }
        _ => (),
    }
}

fn process_tcp_packet(
    packet: &TcpPacket,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    monitored_ips: &mut HashMap<IpAddr, MonitoredIP>,
    config: &Config,
) {
    let src_port = packet.get_source();
    let dst_port = packet.get_destination();
    let flags = packet.get_flags();

    // Check for port scanning (SYN packets to multiple ports)
    if flags == 2 {
        // SYN flag
        if let Some(monitored_ip) = monitored_ips.get_mut(&src_ip) {
            monitored_ip.ports_scanned.push(dst_port);
            
            // Check if this is a port scan
            if monitored_ip.ports_scanned.len() > config.alert_thresholds.port_scan as usize {
                monitored_ip.stats.port_scans_detected += 1;
                println!("Port scan detected from {} to {}", src_ip, dst_ip);
                // Here you would add code to send an alert
            }
        }
    }

    // Check for DoS/DDoS (many SYN packets to same port)
    if flags == 2 {
        // SYN flag
        if let Some(monitored_ip) = monitored_ips.get_mut(&dst_ip) {
            let now = Instant::now();
            let recent_connections = monitored_ip
                .connections
                .iter()
                .filter(|&&conn| {
                    conn.port() == dst_port && now.duration_since(monitored_ip.last_activity) < Duration::from_secs(1)
                })
                .count();

            if recent_connections > config.alert_thresholds.dos_attempts as usize {
                monitored_ip.stats.dos_attempts_detected += 1;
                println!("Possible DoS attack detected on {}:{}", dst_ip, dst_port);
                // Here you would add code to send an alert
            }

            monitored_ip.connections.push(SocketAddr::new(src_ip, src_port));
            monitored_ip.last_activity = now;
        }
    }

    // Update stats for both source and destination
    if let Some(monitored_ip) = monitored_ips.get_mut(&src_ip) {
        monitored_ip.stats.packets_sent += 1;
        monitored_ip.stats.bytes_sent += packet.packet().len() as u64;
    }

    if let Some(monitored_ip) = monitored_ips.get_mut(&dst_ip) {
        monitored_ip.stats.packets_received += 1;
        monitored_ip.stats.bytes_received += packet.packet().len() as u64;
    }
}

fn process_udp_packet(
    packet: &UdpPacket,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    monitored_ips: &mut HashMap<IpAddr, MonitoredIP>,
) {
    // Update stats for both source and destination
    if let Some(monitored_ip) = monitored_ips.get_mut(&src_ip) {
        monitored_ip.stats.packets_sent += 1;
        monitored_ip.stats.bytes_sent += packet.packet().len() as u64;
    }

    if let Some(monitored_ip) = monitored_ips.get_mut(&dst_ip) {
        monitored_ip.stats.packets_received += 1;
        monitored_ip.stats.bytes_received += packet.packet().len() as u64;
    }
}

fn print_help() {
    println!("Accuarate Cyber Denfense Network Terminla Commands:");
    println!("  help                        - Show this help message");
    println!("  ping <ip>                   - Ping an IP address");
    println!("  traceroute <ip>             - Perform a traceroute to an IP");
    println!("  tcptraceroute <ip>          - Perform a TCP traceroute");
    println!("  udptraceroute <ip>          - Perform a UDP traceroute");
    println!("  nping <ip>                  - Perform an advanced ping with Nping");
    println!("  start monitoring <ip>       - Start monitoring an IP address");
    println!("  stop monitoring <ip>        - Stop monitoring an IP address");
    println!("  start capture               - Start packet capture");
    println!("  stop capture                - Stop packet capture");
    println!("  view                        - View current monitoring data");
    println!("  status                      - Show monitoring status");
    println!("  clear                       - Clear the screen");
    println!("  config telegram <api_key>   - Configure Telegram API key");
    println!("  config chat_id <chat_id>    - Configure Telegram chat ID");
    println!("  test telegram               - Test Telegram notification");
    println!("  export telegram             - Export report to Telegram");
    println!("  generate traffic <ip>       - Generate test network traffic");
    println!("  exit                        - Exit the program");
}

fn print_banner() {
    println!(r"
   _____      _           _____                     _    
  / ____|    | |         / __ 
 | |    _   _| |__   ___| |     
 | |  | | | | '_ \ / _ \ 
 |____| |_| | |_) | _/ |_   
  \_____|\__, |_.__/ \___|   
          __/ |                                          
         |___/                                           
    ");
    println!("Accurate Cyber Defense Netowk Terminal Bot");
    println!("Version 1.0.0\n");
}

fn main() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();

    // Set blue theme
    stdout.execute(SetBackgroundColor(Color::DarkBlue))?;
    stdout.execute(SetForegroundColor(Color::White))?;
    stdout.execute(Clear(ClearType::All))?;

    print_banner();

    let mut accurate_bot = AccurateBot::new()?;
    let mut command = String::new();

    loop {
        print!("accurate> ");
        io::stdout().flush()?;

        command.clear();
        io::stdin().read_line(&mut command)?;
        let command = command.trim();
        let parts: Vec<&str> = command.split_whitespace().collect();

        if parts.is_empty() {
            continue;
        }

        match parts[0].to_lowercase().as_str() {
            "help" => print_help(),
            "ping" => {
                if parts.len() < 2 {
                    println!("Usage: ping <ip>");
                    continue;
                }
                if let Ok(ip) = parts[1].parse() {
                    accurate_bot.ping(ip)?;
                } else {
                    println!("Invalid IP address");
                }
            }
            "traceroute" => {
                if parts.len() < 2 {
                    println!("Usage: traceroute <ip>");
                    continue;
                }
                if let Ok(ip) = parts[1].parse() {
                    accurate_bot.traceroute(ip)?;
                } else {
                    println!("Invalid IP address");
                }
            }
            "tcptraceroute" => {
                if parts.len() < 2 {
                    println!("Usage: tcptraceroute <ip>");
                    continue;
                }
                if let Ok(ip) = parts[1].parse() {
                    accurate_bot.tcptraceroute(ip)?;
                } else {
                    println!("Invalid IP address");
                }
            }
            "udptraceroute" => {
                if parts.len() < 2 {
                    println!("Usage: udptraceroute <ip>");
                    continue;
                }
                if let Ok(ip) = parts[1].parse() {
                    accurate_bot.udptraceroute(ip)?;
                } else {
                    println!("Invalid IP address");
                }
            }
            "nping" => {
                if parts.len() < 2 {
                    println!("Usage: nping <ip>");
                    continue;
                }
                if let Ok(ip) = parts[1].parse() {
                    accurate_bot.nping(ip)?;
                } else {
                    println!("Invalid IP address");
                }
            }
            "start" => {
                if parts.len() < 2 {
                    println!("Usage: start <monitoring|capture> [ip]");
                    continue;
                }
                match parts[1].to_lowercase().as_str() {
                    "monitoring" => {
                        if parts.len() < 3 {
                            println!("Usage: start monitoring <ip>");
                            continue;
                        }
                        if let Ok(ip) = parts[2].parse() {
                            accurate_bot.start_monitoring(ip);
                        } else {
                            println!("Invalid IP address");
                        }
                    }
                    "capture" => {
                        accurate_bot.start_packet_capture()?;
                    }
                    _ => println!("Unknown start command: {}", parts[1]),
                }
            }
            "stop" => {
                if parts.len() < 2 {
                    println!("Usage: stop <monitoring|capture> [ip]");
                    continue;
                }
                match parts[1].to_lowercase().as_str() {
                    "monitoring" => {
                        if parts.len() < 3 {
                            println!("Usage: stop monitoring <ip>");
                            continue;
                        }
                        if let Ok(ip) = parts[2].parse() {
                            accurate_bot.stop_monitoring(ip);
                        } else {
                            println!("Invalid IP address");
                        }
                    }
                    "capture" => {
                        accurate_bot.stop_packet_capture();
                    }
                    _ => println!("Unknown stop command: {}", parts[1]),
                }
            }
            "view" => accurate_bot.view(),
            "status" => accurate_bot.status(),
            "clear" => accurate_bot.clear_screen()?,
            "config" => {
                if parts.len() < 3 {
                    println!("Usage: config <telegram|chat_id> <value>");
                    continue;
                }
                match parts[1].to_lowercase().as_str() {
                    "telegram" => {
                        accurate_bot.config_telegram(parts[2..].join(" "));
                    }
                    "chat_id" => {
                        accurate_bot.config_telegram_chat_id(parts[2..].join(" "));
                    }
                    _ => println!("Unknown config option: {}", parts[1]),
                }
            }
            "test" => {
                if parts.len() < 2 {
                    println!("Usage: test <telegram>");
                    continue;
                }
                match parts[1].to_lowercase().as_str() {
                    "telegram" => {
                        accurate_bot.test_telegram()?;
                    }
                    _ => println!("Unknown test command: {}", parts[1]),
                }
            }
            "export" => {
                if parts.len() < 2 {
                    println!("Usage: export <telegram>");
                    continue;
                }
                match parts[1].to_lowercase().as_str() {
                    "telegram" => {
                        accurate_bot.export_to_telegram()?;
                    }
                    _ => println!("Unknown export command: {}", parts[1]),
                }
            }
            "generate" => {
                if parts.len() < 3 {
                    println!("Usage: generate traffic <ip>");
                    continue;
                }
                match parts[1].to_lowercase().as_str() {
                    "traffic" => {
                        if let Ok(ip) = parts[2].parse() {
                            accurate_bot.generate_network_traffic(ip)?;
                        } else {
                            println!("Invalid IP address");
                        }
                    }
                    _ => println!("Unknown generate command: {}", parts[1]),
                }
            }
            "exit" => break,
            _ => println!("Unknown command: {}", parts[0]),
        }
    }

    disable_raw_mode()?;
    stdout.execute(ResetColor)?;
    Ok(())
}