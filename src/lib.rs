use serde::{Deserialize, Serialize};
use serde_xml_rs::from_str;

/// Module for parsing and handling Nmap output files
pub mod gnmap;

/// Represents the type of address in an Nmap scan result
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AddressType {
    /// IPv4 address
    IPv4,
    /// IPv6 address
    IPv6,
    /// MAC address
    MAC,
}

/// Represents the protocol used for port scanning
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PortProtocol {
    /// IP protocol
    Ip,
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
    /// SCTP protocol
    Sctp,
}

/// Represents the state of a host in an Nmap scan
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HostState {
    /// Host is up and responding
    Up,
    /// Host is down or not responding
    Down,
    /// Host state could not be determined
    Unknown,
    /// Host was skipped during scanning
    Skipped,
}

/// Represents the state of a port in an Nmap scan
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    /// Port is open and accepting connections
    #[serde(rename = "open")]
    Open,
    /// Port is closed
    #[serde(rename = "closed")]
    Closed,
    /// Port is filtered by a firewall or other network device
    #[serde(rename = "filtered")]
    Filtered,
    /// Port is unfiltered but state could not be determined
    #[serde(rename = "unfiltered")]
    Unfiltered,
    /// Port could be either open or filtered
    #[serde(rename = "open|filtered")]
    OpenFiltered,
    /// Port could be either closed or filtered
    #[serde(rename = "closed|filtered")]
    ClosedFiltered,
}

/// Method used to determine service information
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceMethod {
    /// Service determined by port number lookup
    Table,
    /// Service determined by active probing
    Probed,
}

/// Type of scan performed by Nmap
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    /// TCP SYN scan
    Syn,
    /// TCP ACK scan
    Ack,
    /// FTP bounce scan
    Bounce,
    /// TCP connect scan
    Connect,
    /// TCP NULL scan
    Null,
    /// TCP XMAS scan
    Xmas,
    /// TCP Window scan
    Window,
    /// TCP Maimon scan
    Maimon,
    /// TCP FIN scan
    Fin,
    /// UDP scan
    Udp,
    /// SCTP INIT scan
    SctpInit,
    /// SCTP COOKIE-ECHO scan
    SctpCookieEcho,
    /// IP protocol scan
    IpProto,
}

/// Information about the scan configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanInfo {
    /// Type of scan performed
    #[serde(rename = "type")]
    pub scan_type: ScanType,
    /// Protocol used for scanning
    #[serde(rename = "protocol")]
    pub protocol: PortProtocol,
    /// Number of services scanned
    #[serde(rename = "numservices")]
    pub num_services: String,
    /// List of services scanned
    #[serde(rename = "services")]
    pub services: Option<String>,
}

/// Main structure representing an Nmap scan run
#[derive(Debug, Serialize, Deserialize)]
pub struct NmapRun {
    /// List of hosts scanned
    #[serde(rename = "host")]
    pub hosts: Vec<Host>,
    /// Scan configuration information
    #[serde(rename = "scaninfo")]
    pub scan_info: Option<ScanInfo>,
    /// Command line arguments used for the scan
    #[serde(rename = "args")]
    pub args: String,
    /// Scanner name (usually "nmap")
    #[serde(rename = "scanner")]
    pub scanner: String,
    /// Nmap version used
    #[serde(rename = "version")]
    pub version: String,
    /// XML output version
    #[serde(rename = "xmloutputversion")]
    pub xml_output_version: String,
    /// Unix timestamp when scan started
    #[serde(rename = "start")]
    pub start: Option<u64>,
    /// Human-readable start time
    #[serde(rename = "startstr")]
    pub start_str: Option<String>,
    /// Verbosity level information
    #[serde(rename = "verbose", skip_serializing_if = "Option::is_none")]
    pub verbose: Option<Verbose>,
    /// Debugging level information
    #[serde(rename = "debugging", skip_serializing_if = "Option::is_none")]
    pub debugging: Option<Debugging>,
    /// Statistics about the scan run
    #[serde(rename = "runstats", skip_serializing_if = "Option::is_none")]
    pub run_stats: Option<RunStats>,
}

/// Verbosity level configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct Verbose {
    /// Verbosity level (0-4)
    #[serde(rename = "level")]
    pub level: i32,
}

/// Debugging level configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct Debugging {
    /// Debug level (0-4)
    #[serde(rename = "level")]
    pub level: i32,
}

/// Statistics about the scan run
#[derive(Debug, Serialize, Deserialize)]
pub struct RunStats {
    /// Information about scan completion
    #[serde(rename = "finished")]
    pub finished: Option<Finished>,
    /// Host statistics
    #[serde(rename = "hosts")]
    pub hosts: Option<HostStats>,
}

/// Information about scan completion
#[derive(Debug, Serialize, Deserialize)]
pub struct Finished {
    /// Unix timestamp when scan finished
    #[serde(rename = "time")]
    pub time: u64,
    /// Human-readable finish time
    #[serde(rename = "timestr")]
    pub time_str: String,
    /// Total time elapsed in seconds
    #[serde(rename = "elapsed")]
    pub elapsed: f64,
    /// Summary of scan results
    #[serde(rename = "summary")]
    pub summary: String,
    /// Exit status
    #[serde(rename = "exit")]
    pub exit: String,
}

/// Statistics about scanned hosts
#[derive(Debug, Serialize, Deserialize)]
pub struct HostStats {
    /// Number of hosts that were up
    #[serde(rename = "up")]
    pub up: u32,
    /// Number of hosts that were down
    #[serde(rename = "down")]
    pub down: u32,
    /// Total number of hosts scanned
    #[serde(rename = "total")]
    pub total: u32,
}

/// Information about a scanned host
#[derive(Debug, Serialize, Deserialize)]
pub struct Host {
    /// Host status information
    #[serde(rename = "status")]
    pub status: Status,
    /// List of addresses associated with the host
    #[serde(rename = "address")]
    pub addresses: Vec<Address>,
    /// Host names associated with the host
    #[serde(rename = "hostnames")]
    pub hostnames: Option<HostNames>,
    /// Port scan results
    #[serde(rename = "ports")]
    pub ports: Option<Ports>,
    /// Unix timestamp when host scan started
    #[serde(rename = "starttime")]
    pub start_time: Option<u64>,
    /// Unix timestamp when host scan ended
    #[serde(rename = "endtime")]
    pub end_time: Option<u64>,
}

/// Host status information
#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    /// State of the host
    #[serde(rename = "state")]
    pub state: HostState,
    /// Reason for the state determination
    #[serde(rename = "reason")]
    pub reason: String,
    /// TTL value from the reason determination
    #[serde(rename = "reason_ttl")]
    pub reason_ttl: String,
}

/// Address information for a host
#[derive(Debug, Serialize, Deserialize)]
pub struct Address {
    /// The address value
    #[serde(rename = "addr")]
    pub addr: String,
    /// Type of address
    #[serde(rename = "addrtype")]
    pub addrtype: AddressType,
    /// Vendor name (for MAC addresses)
    #[serde(rename = "vendor")]
    pub vendor: Option<String>,
}

/// Collection of host names
#[derive(Debug, Serialize, Deserialize)]
pub struct HostNames {
    /// List of host names
    #[serde(rename = "hostname")]
    pub hostnames: Option<Vec<HostName>>,
}

/// Individual host name information
#[derive(Debug, Serialize, Deserialize)]
pub struct HostName {
    /// The host name
    #[serde(rename = "name")]
    pub name: String,
    /// Type of host name
    #[serde(rename = "type")]
    pub hostname_type: HostNameType,
}

/// Type of host name
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HostNameType {
    /// User-specified host name
    User,
    /// PTR record from reverse DNS lookup
    PTR,
}

/// Collection of port scan results
#[derive(Debug, Serialize, Deserialize)]
pub struct Ports {
    /// List of scanned ports
    #[serde(rename = "port")]
    pub ports: Option<Vec<Port>>,
    /// Information about ports not fully scanned
    #[serde(rename = "extraports")]
    pub extraports: Option<Vec<ExtraPorts>>,
}

/// Information about ports not fully scanned
#[derive(Debug, Serialize, Deserialize)]
pub struct ExtraPorts {
    /// State of the extra ports
    #[serde(rename = "state")]
    pub state: PortState,
    /// Number of ports in this state
    #[serde(rename = "count")]
    pub count: u32,
    /// Additional reasons for port state
    #[serde(rename = "extrareasons")]
    pub extrareasons: Option<Vec<ExtraReasons>>,
}

/// Additional reasons for port state
#[derive(Debug, Serialize, Deserialize)]
pub struct ExtraReasons {
    /// Reason description
    #[serde(rename = "reason")]
    pub reason: String,
    /// Number of ports with this reason
    #[serde(rename = "count")]
    pub count: u32,
    /// Protocol used
    #[serde(rename = "proto")]
    pub protocol: Option<PortProtocol>,
    /// Port numbers affected
    #[serde(rename = "ports")]
    pub ports: Option<String>,
}

/// Information about a specific port
#[derive(Debug, Serialize, Deserialize)]
pub struct Port {
    /// Protocol used
    #[serde(rename = "protocol")]
    pub protocol: PortProtocol,
    /// Port number
    #[serde(rename = "portid")]
    pub port_id: u32,
    /// Port state details
    #[serde(rename = "state")]
    pub state: PortStateDetails,
    /// Service information
    #[serde(rename = "service")]
    pub service: Option<Service>,
    /// NSE script results
    #[serde(rename = "script")]
    pub scripts: Option<Vec<Script>>,
}

/// Detailed port state information
#[derive(Debug, Serialize, Deserialize)]
pub struct PortStateDetails {
    /// State of the port
    #[serde(rename = "state")]
    pub state: PortState,
    /// Reason for the state determination
    #[serde(rename = "reason")]
    pub reason: String,
    /// TTL value from the reason determination
    #[serde(rename = "reason_ttl")]
    pub reason_ttl: String,
    /// IP address that provided the reason
    #[serde(rename = "reason_ip")]
    pub reason_ip: Option<String>,
}

/// Service information for a port
#[derive(Debug, Serialize, Deserialize)]
pub struct Service {
    /// Service name
    #[serde(rename = "name")]
    pub name: String,
    /// Product name
    #[serde(rename = "product")]
    pub product: Option<String>,
    /// Product version
    #[serde(rename = "version")]
    pub version: Option<String>,
    /// Additional service information
    #[serde(rename = "extrainfo")]
    pub extra_info: Option<String>,
    /// Method used to determine service
    #[serde(rename = "method")]
    pub method: ServiceMethod,
    /// Confidence level in service detection (0-10)
    #[serde(rename = "conf")]
    pub confidence: u8,
    /// Operating system type
    #[serde(rename = "ostype")]
    pub os_type: Option<String>,
    /// Device type
    #[serde(rename = "devicetype")]
    pub device_type: Option<String>,
    /// Tunnel type (if service is tunneled)
    #[serde(rename = "tunnel")]
    pub tunnel: Option<String>,
    /// Common Platform Enumeration (CPE) names
    #[serde(rename = "cpe")]
    pub cpes: Option<Vec<String>>,
}

/// NSE script results
#[derive(Debug, Serialize, Deserialize)]
pub struct Script {
    /// Script identifier
    #[serde(rename = "id")]
    pub id: String,
    /// Script output
    #[serde(rename = "output")]
    pub output: String,
}

/// Parses Nmap XML output into a structured format
///
/// # Examples
///
/// ```
/// use nmap::parse_nmap_xml;
///
/// let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
/// <nmaprun scanner="nmap" args="nmap -sS -p 80 example.com" version="7.92" xmloutputversion="1.05">
///   <host>
///     <status state="up" reason="syn-ack" reason_ttl="0"/>
///     <address addr="192.168.1.1" addrtype="ipv4"/>
///     <ports>
///       <port protocol="tcp" portid="80">
///         <state state="open" reason="syn-ack" reason_ttl="64"/>
///         <service name="http" method="table" conf="3"/>
///       </port>
///     </ports>
///   </host>
/// </nmaprun>"#;
///
/// let result = parse_nmap_xml(xml);
/// assert!(result.is_ok());
///
/// let nmap_run = result.unwrap();
/// assert_eq!(nmap_run.scanner, "nmap");
/// assert_eq!(nmap_run.version, "7.92");
/// assert_eq!(nmap_run.hosts.len(), 1);
///
/// let host = &nmap_run.hosts[0];
/// assert_eq!(host.addresses[0].addr, "192.168.1.1");
/// assert_eq!(host.addresses[0].addrtype, nmap::AddressType::IPv4);
/// ```
pub fn parse_nmap_xml(xml_content: &str) -> Result<NmapRun, Box<dyn std::error::Error>> {
    let nmap_run: NmapRun = from_str(xml_content)?;
    Ok(nmap_run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_status() {
        let xml = r#"<status state="up" reason="arp-response" reason_ttl="0"/>"#;
        let status: Status = from_str(xml).expect("Failed to parse Status");
        assert_eq!(status.state, HostState::Up);
        assert_eq!(status.reason, "arp-response");
        assert_eq!(status.reason_ttl, "0");
    }

    #[test]
    fn test_parse_port() {
        let xml = r#"<port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack" reason_ttl="64"/>
            <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu 4ubuntu0.5" method="probed" conf="10"/>
        </port>"#;

        let port: Port = from_str(xml).expect("Failed to parse Port");

        assert_eq!(port.protocol, PortProtocol::Tcp);
        assert_eq!(port.port_id, 22);
        assert_eq!(port.state.state, PortState::Open);
        assert_eq!(port.state.reason, "syn-ack");
        assert_eq!(port.state.reason_ttl, "64");

        let service = port.service.expect("Expected service to be present");
        assert_eq!(service.name, "ssh");
        assert_eq!(service.product, Some("OpenSSH".to_string()));
        assert_eq!(service.version, Some("8.2p1".to_string()));
        assert_eq!(service.extra_info, Some("Ubuntu 4ubuntu0.5".to_string()));
        assert_eq!(service.method, ServiceMethod::Probed);
        assert_eq!(service.confidence, 10);
    }

    #[test]
    fn test_parse_nmap_xml() {
        let xml_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sS -Pn -A -O -T4 -oA local 1.2.3.4/24" 
         start="1741619519" startstr="Mon Mar 10 10:11:59 2025" 
         version="7.92" xmloutputversion="1.05">
    <scaninfo type="syn" protocol="tcp" numservices="1" services="10"/>
    <host starttime="1741619528" endtime="1741619840">
        <status state="up" reason="arp-response" reason_ttl="0"/>
        <address addr="1.1.1.1" addrtype="ipv4"/>
        <address addr="AA:AA:AA:AA:AA:AA" addrtype="mac" vendor="A"/>
        <hostnames>
            <hostname name="test.local" type="PTR"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open" reason="syn-ack" reason_ttl="64"/>
                <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu 4ubuntu0.5" method="probed" conf="10"/>
            </port>
            <port protocol="tcp" portid="80">
                <state state="open" reason="syn-ack" reason_ttl="64"/>
                <service name="http" product="nginx" version="1.18.0" method="probed" conf="10"/>
            </port>
            <extraports state="filtered" count="998">
                <extrareasons reason="no-response" count="998" proto="tcp" ports="1-21,23-79,81-65535"/>
            </extraports>
        </ports>
    </host>
    <host>
        <status state="up" reason="arp-response" reason_ttl="0"/>
        <address addr="2.2.2.2" addrtype="ipv4"/>
        <address addr="BB:BB:BB:BB:BB:BB" addrtype="mac" vendor="B"/>
        <ports>
            <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack" reason_ttl="64"/>
                <service name="https" product="Apache httpd" version="2.4.41" method="probed" conf="10"/>
            </port>
        </ports>
    </host>
</nmaprun>"#;

        let nmap_run = parse_nmap_xml(xml_content).expect("Failed to parse XML");

        assert_eq!(nmap_run.args, "nmap -sS -Pn -A -O -T4 -oA local 1.2.3.4/24");
        assert_eq!(nmap_run.scanner, "nmap");
        assert_eq!(nmap_run.version, "7.92");
        assert_eq!(nmap_run.xml_output_version, "1.05");
        assert_eq!(nmap_run.start, Some(1741619519));
        assert_eq!(
            nmap_run.start_str,
            Some("Mon Mar 10 10:11:59 2025".to_string())
        );

        // Test scaninfo
        if let Some(scan_info) = &nmap_run.scan_info {
            assert_eq!(scan_info.scan_type, ScanType::Syn);
            assert_eq!(scan_info.protocol, PortProtocol::Tcp);
            assert!(scan_info.services.is_some());
        } else {
            panic!("Expected scaninfo to be present");
        }

        assert_eq!(nmap_run.hosts.len(), 2);

        let host0 = &nmap_run.hosts[0];
        assert_eq!(host0.status.state, HostState::Up);
        assert_eq!(host0.status.reason, "arp-response");
        assert_eq!(host0.status.reason_ttl, "0");
        assert_eq!(host0.addresses[0].addr, "1.1.1.1");
        assert_eq!(host0.addresses[0].addrtype, AddressType::IPv4);
        assert_eq!(host0.addresses[1].addrtype, AddressType::MAC);
        assert_eq!(host0.addresses[1].vendor, Some("A".to_string()));
        assert_eq!(host0.start_time, Some(1741619528));
        assert_eq!(host0.end_time, Some(1741619840));

        if let Some(hostnames) = &host0.hostnames {
            if let Some(hostname_vec) = &hostnames.hostnames {
                assert_eq!(hostname_vec[0].name, "test.local");
                assert_eq!(hostname_vec[0].hostname_type, HostNameType::PTR);
            } else {
                panic!("Expected hostname vector to be present");
            }
        } else {
            panic!("Expected hostnames for first host");
        }

        // Test ports for host0
        if let Some(ports) = &host0.ports {
            if let Some(port_vec) = &ports.ports {
                assert_eq!(port_vec.len(), 2);

                // Check first port (SSH)
                let ssh_port = &port_vec[0];
                assert_eq!(ssh_port.protocol, PortProtocol::Tcp);
                assert_eq!(ssh_port.port_id, 22);
                assert_eq!(ssh_port.state.state, PortState::Open);
                assert_eq!(ssh_port.state.reason, "syn-ack");

                if let Some(service) = &ssh_port.service {
                    assert_eq!(service.name, "ssh");
                    assert_eq!(service.product, Some("OpenSSH".to_string()));
                    assert_eq!(service.version, Some("8.2p1".to_string()));
                    assert_eq!(service.method, ServiceMethod::Probed);
                    assert_eq!(service.confidence, 10);
                } else {
                    panic!("Expected service info for SSH port");
                }

                // Check second port (HTTP)
                let http_port = &port_vec[1];
                assert_eq!(http_port.protocol, PortProtocol::Tcp);
                assert_eq!(http_port.port_id, 80);

                if let Some(service) = &http_port.service {
                    assert_eq!(service.name, "http");
                    assert_eq!(service.product, Some("nginx".to_string()));
                    assert_eq!(service.method, ServiceMethod::Probed);
                } else {
                    panic!("Expected service info for HTTP port");
                }
            } else {
                panic!("Expected port vector to be present");
            }

            // Check extraports
            if let Some(extraports) = &ports.extraports {
                assert_eq!(extraports[0].state, PortState::Filtered);
                assert_eq!(extraports[0].count, 998);

                if let Some(extrareasons) = &extraports[0].extrareasons {
                    assert_eq!(extrareasons[0].reason, "no-response");
                    assert_eq!(extrareasons[0].count, 998);
                } else {
                    panic!("Expected extrareasons in extraports");
                }
            } else {
                panic!("Expected extraports information");
            }
        } else {
            panic!("Expected ports information for host0");
        }

        // Test ports for host1
        let host1 = &nmap_run.hosts[1];
        if let Some(ports) = &host1.ports {
            if let Some(port_vec) = &ports.ports {
                assert_eq!(port_vec.len(), 1);

                let https_port = &port_vec[0];
                assert_eq!(https_port.protocol, PortProtocol::Tcp);
                assert_eq!(https_port.port_id, 443);
                assert_eq!(https_port.state.state, PortState::Open);

                if let Some(service) = &https_port.service {
                    assert_eq!(service.name, "https");
                    assert_eq!(service.product, Some("Apache httpd".to_string()));
                    assert_eq!(service.version, Some("2.4.41".to_string()));
                    assert_eq!(service.method, ServiceMethod::Probed);
                } else {
                    panic!("Expected service info for HTTPS port");
                }
            } else {
                panic!("Expected port vector to be present");
            }
        } else {
            panic!("Expected ports information for host1");
        }
    }

    #[test]
    fn test_serialize_port() {
        let port = Port {
            protocol: PortProtocol::Tcp,
            port_id: 80,
            state: PortStateDetails {
                state: PortState::Open,
                reason: "syn-ack".to_string(),
                reason_ttl: "64".to_string(),
                reason_ip: None,
            },
            service: Some(Service {
                name: "http".to_string(),
                product: Some("nginx".to_string()),
                version: Some("1.18.0".to_string()),
                extra_info: None,
                method: ServiceMethod::Probed,
                confidence: 10,
                os_type: None,
                device_type: None,
                tunnel: None,
                cpes: None,
            }),
            scripts: None,
        };

        // Serialize to JSON instead of XML
        let json = serde_json::to_string_pretty(&port).expect("Failed to serialize Port to JSON");
        println!("Serialized JSON:\n{}", json);

        // Verify JSON contains expected values
        assert!(json.contains(r#""protocol": "tcp"#));
        assert!(json.contains(r#""portid": 80"#));
        assert!(json.contains(r#""state": "open"#));
        assert!(json.contains(r#""name": "http"#));
        assert!(json.contains(r#""product": "nginx"#));
        assert!(json.contains(r#""version": "1.18.0"#));
        assert!(json.contains(r#""method": "probed"#));
        assert!(json.contains(r#""conf": 10"#));

        // Test round-trip with JSON
        let parsed_port: Port =
            serde_json::from_str(&json).expect("Failed to parse serialized Port JSON");
        assert_eq!(parsed_port.protocol, port.protocol);
        assert_eq!(parsed_port.port_id, port.port_id);
        assert_eq!(parsed_port.state.state, port.state.state);
        assert_eq!(parsed_port.state.reason, port.state.reason);
        assert_eq!(parsed_port.state.reason_ttl, port.state.reason_ttl);

        let parsed_service = parsed_port.service.expect("Expected service to be present");
        let original_service = port.service.expect("Expected service to be present");
        assert_eq!(parsed_service.name, original_service.name);
        assert_eq!(parsed_service.product, original_service.product);
        assert_eq!(parsed_service.version, original_service.version);
        assert_eq!(parsed_service.method, original_service.method);
        assert_eq!(parsed_service.confidence, original_service.confidence);
    }
}
