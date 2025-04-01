use crate::{
    Address, AddressType, ExtraPorts, ExtraReasons, Host, HostName, HostNameType, HostNames,
    HostState, NmapRun, Port, PortProtocol, PortState, PortStateDetails, Ports, Service,
    ServiceMethod, Status,
};
use std::collections::HashMap;
use std::io::{self, BufRead};

/// Parses Nmap greppable (-oG) output format into a structured format
///
/// # Examples
///
/// ```
/// use std::io::Cursor;
/// use nmap::gnmap::parse_gnmap;
///
/// let gnmap_data = r#"# Nmap 7.92 scan initiated Mon Mar 10 10:11:59 2025 as: nmap -sS -p 80 example.com
/// Host: 192.168.1.1 ()    Status: Up
/// Host: 192.168.1.1 ()    Ports: 80/open/tcp//http//nginx/
/// # Nmap done at Mon Mar 10 10:12:01 2025 -- 1 IP address (1 host up) scanned in 2.49 seconds"#;
///
/// let cursor = Cursor::new(gnmap_data);
/// let result = parse_gnmap(cursor);
/// assert!(result.is_ok());
///
/// let nmap_run = result.unwrap();
/// assert_eq!(nmap_run.hosts.len(), 1);
///
/// let host = &nmap_run.hosts[0];
/// assert_eq!(host.addresses[0].addr, "192.168.1.1");
/// assert_eq!(host.status.state, nmap::HostState::Up);
///
/// if let Some(ports) = &host.ports {
///     if let Some(port_list) = &ports.ports {
///         assert_eq!(port_list.len(), 1);
///         assert_eq!(port_list[0].port_id, 80);
///         assert_eq!(port_list[0].state.state, nmap::PortState::Open);
///         if let Some(service) = &port_list[0].service {
///             assert_eq!(service.name, "http");
///             assert_eq!(service.product, Some("nginx".to_string()));
///         }
///     }
/// }
/// ```
pub fn parse_gnmap<R: io::Read>(reader: R) -> Result<NmapRun, String> {
    let reader = io::BufReader::new(reader);
    let mut lines = reader.lines();

    let header = lines
        .next()
        .ok_or_else(|| "Empty gnmap file".to_string())?
        .map_err(|e| format!("Failed to read header: {}", e))?;

    let args = header
        .split("as: ")
        .nth(1)
        .ok_or_else(|| "Invalid header format".to_string())?
        .to_string();

    let mut hosts = Vec::new();
    let mut host_map: HashMap<String, usize> = HashMap::new();

    while let Some(Ok(line)) = lines.next() {
        if line.starts_with("# Nmap done") {
            continue;
        }

        if line.contains("Status: Up") {
            let ip = extract_ip(&line)?;
            let hostname = extract_hostname(&line);

            if !host_map.contains_key(&ip) {
                let index = hosts.len();
                let mut host = Host {
                    status: Status {
                        state: HostState::Up,
                        reason: "user-set".to_string(),
                        reason_ttl: "0".to_string(),
                    },
                    addresses: vec![Address {
                        addr: ip.clone(),
                        addrtype: AddressType::IPv4,
                        vendor: None,
                    }],
                    hostnames: None,
                    ports: None,
                    start_time: None,
                    end_time: None,
                };

                if let Some(name) = hostname {
                    host.add_hostname(name, HostNameType::User);
                }

                hosts.push(host);
                host_map.insert(ip, index);
            }
        } else if line.contains("Ports:") {
            let ip = extract_ip(&line)?;

            let host_index = *host_map
                .get(&ip)
                .ok_or_else(|| format!("Found ports for unknown host: {}", ip))?;

            let ports_section = line
                .split("Ports: ")
                .nth(1)
                .ok_or_else(|| "Invalid ports line format".to_string())?;

            let mut port_list = Vec::new();
            let mut ignored_count = 0;

            for port_entry in ports_section.split("\t").next().unwrap().split(", ") {
                if port_entry.contains("Ignored State:") {
                    if let Some(count) = port_entry
                        .split("(")
                        .nth(1)
                        .and_then(|s| s.split(")").next())
                    {
                        if let Ok(count) = count.parse::<u32>() {
                            ignored_count = count;
                        }
                    }
                    continue;
                }

                let parts: Vec<&str> = port_entry.split("/").collect();
                if parts.len() >= 7 {
                    let port_id = parts[0].parse::<u16>().unwrap_or(0);
                    let state = match parts[1] {
                        "open" => PortState::Open,
                        "closed" => PortState::Closed,
                        "filtered" => PortState::Filtered,
                        "unfiltered" => PortState::Unfiltered,
                        "open|filtered" => PortState::OpenFiltered,
                        "closed|filtered" => PortState::ClosedFiltered,
                        _ => PortState::Open,
                    };
                    let protocol = match parts[2] {
                        "tcp" => PortProtocol::Tcp,
                        "udp" => PortProtocol::Udp,
                        "sctp" => PortProtocol::Sctp,
                        "ip" => PortProtocol::Ip,
                        _ => PortProtocol::Tcp,
                    };

                    let service_name = parts[4].to_string();
                    let service_details = parts[6].to_string();

                    let mut service = Service {
                        name: service_name,
                        product: None,
                        version: None,
                        extra_info: None,
                        method: ServiceMethod::Table,
                        confidence: 3,
                        os_type: None,
                        device_type: None,
                        tunnel: None,
                        cpes: None,
                    };

                    if !service_details.is_empty() {
                        let details = service_details.trim_end_matches('/');
                        let first_word = details.split_whitespace().next().unwrap_or("");
                        service.product = Some(first_word.to_string());

                        if details.contains(' ') {
                            let mut parts = details.split_whitespace();
                            let _ = parts.next();
                            let rest: String = parts.collect::<Vec<_>>().join(" ");

                            if let Some(ver_idx) = rest.find(|c: char| c.is_numeric()) {
                                let version_end = rest[ver_idx..]
                                    .find(|c: char| !c.is_numeric() && c != '.' && c != '-')
                                    .map(|i| ver_idx + i)
                                    .unwrap_or(rest.len());
                                service.version = Some(rest[ver_idx..version_end].to_string());

                                if let Some(extra_start) = rest.find('(') {
                                    if let Some(extra_end) = rest.rfind(')') {
                                        service.extra_info = Some(
                                            rest[extra_start + 1..extra_end].trim().to_string(),
                                        );
                                    }
                                }
                            }
                        }

                        service.method = ServiceMethod::Probed;
                        service.confidence = 10;
                    }

                    let port = Port {
                        protocol,
                        port_id: port_id as u32,
                        state: PortStateDetails {
                            state,
                            reason: "syn-ack".to_string(),
                            reason_ttl: "0".to_string(),
                            reason_ip: None,
                        },
                        service: Some(service),
                        scripts: None,
                    };

                    port_list.push(port);
                }
            }

            if !port_list.is_empty() || ignored_count > 0 {
                let mut extra_ports = None;
                if ignored_count > 0 {
                    extra_ports = Some(vec![ExtraPorts {
                        state: PortState::Closed,
                        count: ignored_count,
                        extrareasons: Some(vec![ExtraReasons {
                            reason: "conn-refused".to_string(),
                            count: ignored_count,
                            protocol: None,
                            ports: None,
                        }]),
                    }]);
                }

                hosts[host_index].ports = Some(Ports {
                    ports: Some(port_list),
                    extraports: extra_ports,
                });
            }
        }
    }

    let nmap_run = NmapRun {
        scanner: "nmap".to_string(),
        args,
        start: None,
        start_str: None,
        version: "7.92".to_string(),
        xml_output_version: "1.05".to_string(),
        scan_info: None,
        verbose: None,
        debugging: None,
        hosts,
        run_stats: None,
    };

    Ok(nmap_run)
}

fn extract_ip(line: &str) -> Result<String, String> {
    line.split_whitespace()
        .nth(1)
        .ok_or_else(|| "IP address not found".to_string())
        .map(|s| s.to_string())
}

fn extract_hostname(line: &str) -> Option<String> {
    if line.contains("(") && line.contains(")") {
        let start = line.find("(")? + 1;
        let end = line.find(")")?;
        if start < end {
            let hostname = &line[start..end];
            if !hostname.is_empty() {
                return Some(hostname.to_string());
            }
        }
    }
    None
}

trait HostExt {
    fn add_hostname(&mut self, name: String, hostname_type: HostNameType);
}

impl HostExt for Host {
    fn add_hostname(&mut self, name: String, hostname_type: HostNameType) {
        if name.is_empty() {
            return;
        }

        let hostname = HostName {
            name,
            hostname_type,
        };

        match &mut self.hostnames {
            Some(hostnames) => {
                if let Some(ref mut hostname_vec) = hostnames.hostnames {
                    hostname_vec.push(hostname);
                } else {
                    hostnames.hostnames = Some(vec![hostname]);
                }
            }
            None => {
                self.hostnames = Some(HostNames {
                    hostnames: Some(vec![hostname]),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_parse_gnmap() {
        let gnmap_data = r#"# Nmap 7.92 scan initiated Mon Mar 10 10:11:59 2025 as: nmap -sS -Pn -A -O -T4 -oA local 192.168.0.0/24
Host: 1.1.1.1 ()	Status: Up
Host: 1.1.1.1 ()	Ports: 1443/open/tcp//ssl|upnp//apache/
Host: 2.2.2.2 ()	Status: Up
Host: 2.2.2.2 ()	Ports: 80/open/tcp//http//nginx/, 443/open/tcp//ssl|http//nginx/, 8080/open/tcp//http//nginx/
Host: 3.3.3.3 (three.local)	Status: Up
Host: 3.3.3.3 (three.local)	Ports: 	Ignored State: closed (1000)
# Nmap done at Mon Mar 10 10:17:20 2025 -- 256 IP addresses (15 hosts up) scanned in 320.49 seconds"#;

        let cursor = Cursor::new(gnmap_data);
        let result = parse_gnmap(cursor);

        assert!(result.is_ok(), "Failed to parse gnmap: {:?}", result.err());

        let nmap_run = result.unwrap();
        assert_eq!(nmap_run.hosts.len(), 3, "Expected 3 hosts");

        let host_two = nmap_run
            .hosts
            .iter()
            .find(|h| h.addresses.iter().any(|a| a.addr == "2.2.2.2"));

        assert!(host_two.is_some(), "Host 2.2.2.2 not found");
        let host = host_two.unwrap();

        assert_eq!(host.status.state, HostState::Up);

        if let Some(ports) = &host.ports {
            if let Some(port_list) = &ports.ports {
                let http_port = port_list.iter().find(|p| p.port_id == 80);
                assert!(http_port.is_some(), "HTTP port not found");

                let https_port = port_list.iter().find(|p| p.port_id == 443);
                assert!(https_port.is_some(), "HTTPS port not found");

                if let Some(port) = http_port {
                    assert_eq!(port.state.state, PortState::Open);
                    if let Some(service) = &port.service {
                        assert_eq!(service.name, "http");
                        assert_eq!(service.product, Some("nginx".to_string()));
                        assert_eq!(service.version, None);
                    }
                }

                let apache_host = nmap_run
                    .hosts
                    .iter()
                    .find(|h| h.addresses.iter().any(|a| a.addr == "1.1.1.1"))
                    .expect("Apache host not found");

                if let Some(apache_ports) = &apache_host.ports {
                    if let Some(port_list) = &apache_ports.ports {
                        let upnp_port = port_list.iter().find(|p| p.port_id == 1443);
                        assert!(upnp_port.is_some(), "UPnP port not found");

                        if let Some(port) = upnp_port {
                            if let Some(service) = &port.service {
                                assert_eq!(service.name, "ssl|upnp");
                                assert_eq!(service.product, Some("apache".to_string()));
                            } else {
                                panic!("No service info for UPnP port");
                            }
                        }
                    }
                }
            } else {
                panic!("No ports found for host 2.2.2.2");
            }
        } else {
            panic!("No ports found for host 2.2.2.2");
        }

        let host_with_hostname = nmap_run
            .hosts
            .iter()
            .find(|h| h.addresses.iter().any(|a| a.addr == "3.3.3.3"));

        if let Some(host) = host_with_hostname {
            assert!(host.hostnames.is_some(), "No hostnames for 3.3.3.3");
            if let Some(hostnames) = &host.hostnames {
                if let Some(hostname_vec) = &hostnames.hostnames {
                    assert!(!hostname_vec.is_empty(), "Empty hostnames list");
                    assert_eq!(hostname_vec[0].name, "three.local");
                } else {
                    panic!("No hostname vector found");
                }
            }
        } else {
            panic!("Host 3.3.3.3 not found");
        }
    }
}
