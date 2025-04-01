use clap::{Parser, Subcommand};
use colored::Colorize;
use log::{debug, error, info};
use std::collections::HashMap;
use std::fs;
use std::io::{self, stdin, BufReader, Cursor, IsTerminal, Read};
use std::path::Path;
use std::process;

#[derive(Parser)]
#[command(name = "nmap-helper")]
#[command(author = "Nmap-rs contributors")]
#[command(version)]
#[command(about = "Helper tool for Nmap output files", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Convert {
        input: Option<String>,

        #[arg(short, long)]
        output: Option<String>,

        #[arg(short, long)]
        pretty: bool,

        #[arg(short, long)]
        format: Option<String>,
    },

    Nmap {
        input: Option<String>,

        #[arg(long = "sort")]
        sort: bool,

        #[arg(long = "nmap-args", default_value = "")]
        nmap_args: String,

        #[arg(long = "single")]
        single: bool,

        #[arg(long = "insert-target")]
        insert_target: Option<String>,
    },
}

enum NmapFormat {
    Xml,
    Gnmap,
    NormalNmap, // Regular (non-greppable) nmap output
    Unknown,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("off"))
        .format(|buf, record| {
            use std::io::Write;
            let level = match record.level() {
                log::Level::Error => "ERROR".red().bold(),
                log::Level::Warn => "WARN".yellow().bold(),
                log::Level::Info => "INFO".green().bold(),
                log::Level::Debug => "DEBUG".blue().bold(),
                log::Level::Trace => "TRACE".purple().bold(),
            };
            writeln!(
                buf,
                "{} [{}] {}",
                chrono::Local::now()
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string()
                    .dimmed(),
                level,
                record.args()
            )
        })
        .init();

    debug!("Starting nmap-helper");

    let cli = Cli::parse();

    match &cli.command {
        Commands::Convert {
            input,
            output,
            pretty,
            format,
        } => {
            convert_input(input, output, *pretty, format);
        }
        Commands::Nmap {
            input,
            sort,
            nmap_args,
            single,
            insert_target,
        } => {
            generate_nmap_commands(input, *sort, nmap_args, *single, insert_target);
        }
    }

    info!("Operation completed successfully");
}

fn detect_format_from_content(content: &[u8]) -> NmapFormat {
    let content_start = String::from_utf8_lossy(&content[..content.len().min(2048)]);
    let lines: Vec<&str> = content_start.lines().collect();

    if content_start.trim_start().starts_with("<?xml") || content_start.contains("<nmaprun") {
        debug!("Detected XML format from content");
        return NmapFormat::Xml;
    }

    if content_start.trim_start().starts_with("# Nmap") {
        if lines.len() > 1 && content_start.contains("Host: ") {
            debug!("Detected greppable (.gnmap) format from content");
            return NmapFormat::Gnmap;
        }

        if lines.len() > 1 && content_start.contains("Nmap scan report") {
            debug!("Detected normal nmap output (not greppable format)");
            return NmapFormat::NormalNmap;
        }
    }

    NmapFormat::Unknown
}

fn detect_format(input_path: &str) -> Result<NmapFormat, String> {
    let file = match fs::File::open(input_path) {
        Ok(file) => file,
        Err(e) => return Err(format!("Failed to open file {}: {}", input_path, e)),
    };

    let mut reader = BufReader::new(file);

    let mut buffer = [0; 2048];
    let n = reader
        .read(&mut buffer)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    let format = detect_format_from_content(&buffer[..n]);

    match format {
        NmapFormat::NormalNmap => {
            Err(format!("The file {} appears to be a standard Nmap output file, not a greppable (-oG) format. \
                              Please use the greppable output format (-oG) or XML format (-oX) with Nmap.", input_path))
        }
        NmapFormat::Unknown => {
            // Check the file extension as a fallback
            let extension = Path::new(input_path)
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("");

            match extension.to_lowercase().as_str() {
                "xml" => {
                    debug!("Using file extension to determine format: XML");
                    Ok(NmapFormat::Xml)
                },
                "gnmap" => {
                    debug!("Using file extension to determine format: GNMAP");
                    Ok(NmapFormat::Gnmap)
                },
                _ => {
                    Err(format!("Unable to determine file format for {}. The file should be a valid Nmap XML (-oX) or greppable (-oG) file.", input_path))
                }
            }
        }
        _ => Ok(format),
    }
}

fn read_stdin_content() -> Result<Vec<u8>, String> {
    let mut buffer = Vec::new();
    match stdin().read_to_end(&mut buffer) {
        Ok(_) => {
            debug!("Successfully read {} bytes from stdin", buffer.len());
            if buffer.is_empty() {
                return Err("No data received from stdin".to_string());
            }
            Ok(buffer)
        }
        Err(e) => Err(format!("Failed to read from stdin: {}", e)),
    }
}

fn process_content_with_format(
    content: Vec<u8>,
    format: NmapFormat,
) -> Result<nmap::NmapRun, String> {
    match format {
        NmapFormat::Xml => {
            match String::from_utf8(content) {
                Ok(xml_str) => Ok(parse_xml_content(&xml_str)),
                Err(e) => Err(format!("Failed to decode XML content as UTF-8: {}", e))
            }
        },
        NmapFormat::Gnmap => {
            // For gnmap, we pass the bytes directly
            Ok(parse_gnmap_content(Cursor::new(content)))
        },
        NmapFormat::NormalNmap => {
            Err("This appears to be a standard Nmap output file, not a greppable (-oG) format. Please use the greppable output format (-oG) or XML format (-oX) with Nmap.".to_string())
        },
        NmapFormat::Unknown => {
            Err("Unable to detect format from content. Please specify format using --format option.".to_string())
        }
    }
}

fn print_error(msg: &str) {
    eprintln!("{}: {}", "ERROR".red().bold(), msg);
    error!("{}", msg);
}

fn fatal_error(msg: &str) -> ! {
    print_error(msg);
    process::exit(1);
}

fn convert_input(
    input_path: &Option<String>,
    output_path: &Option<String>,
    pretty: bool,
    forced_format: &Option<String>,
) {
    let reading_from_stdin = match input_path {
        None => {
            if stdin().is_terminal() {
                fatal_error("No input file specified and no data piped to stdin. Please provide an input file or pipe data to stdin.");
            }
            true
        }
        Some(path) if path == "-" => true,
        _ => false,
    };

    if reading_from_stdin {
        info!("Reading from stdin");
    } else {
        let path = input_path.as_ref().unwrap();
        info!("Processing file: {}", path);
    }

    let format = if let Some(fmt) = forced_format {
        match fmt.to_lowercase().as_str() {
            "xml" => {
                info!("Forced format: XML");
                NmapFormat::Xml
            }
            "gnmap" => {
                info!("Forced format: GNMAP");
                NmapFormat::Gnmap
            }
            _ => {
                fatal_error(&format!(
                    "Invalid format specified: {}. Valid formats are 'xml' or 'gnmap'.",
                    fmt
                ));
            }
        }
    } else if reading_from_stdin {
        info!("Auto-detecting format from stdin content");
        let content = match read_stdin_content() {
            Ok(bytes) => bytes,
            Err(e) => {
                fatal_error(&e);
            }
        };

        let detected_format = detect_format_from_content(&content);

        match detected_format {
            NmapFormat::NormalNmap => {
                fatal_error("This appears to be a standard Nmap output file, not a greppable (-oG) format. Please use the greppable output format (-oG) or XML format (-oX) with Nmap.");
            }
            NmapFormat::Unknown => {
                fatal_error("Unable to detect format from stdin content. Please specify format using --format option.");
            }
            _ => {
                info!("Processing stdin content");

                match process_content_with_format(content, detected_format) {
                    Ok(nmap_run) => {
                        output_json(nmap_run, output_path, pretty);
                        return;
                    }
                    Err(e) => {
                        fatal_error(&e);
                    }
                }
            }
        }
    } else {
        let path = input_path.as_ref().unwrap();
        match detect_format(path) {
            Ok(fmt) => fmt,
            Err(e) => {
                fatal_error(&e);
            }
        }
    };

    let nmap_run = if reading_from_stdin {
        match format {
            NmapFormat::Xml => {
                info!("Processing as XML format");
                process_xml_stdin()
            }
            NmapFormat::Gnmap => {
                info!("Processing as greppable (.gnmap) format");
                process_gnmap_stdin()
            }
            NmapFormat::NormalNmap => {
                fatal_error("This appears to be a standard Nmap output file, not a greppable (-oG) format. Please use the greppable output format (-oG) or XML format (-oX) with Nmap.");
            }
            NmapFormat::Unknown => {
                fatal_error("Unsupported file format for stdin");
            }
        }
    } else {
        match format {
            NmapFormat::Xml => {
                info!("Processing as XML format");
                process_xml_file(input_path.as_ref().unwrap())
            }
            NmapFormat::Gnmap => {
                info!("Processing as greppable (.gnmap) format");
                process_gnmap_file(input_path.as_ref().unwrap())
            }
            NmapFormat::NormalNmap => {
                fatal_error("This appears to be a standard Nmap output file, not a greppable (-oG) format. Please use the greppable output format (-oG) or XML format (-oX) with Nmap.");
            }
            NmapFormat::Unknown => {
                fatal_error(&format!(
                    "Unsupported file format for {}",
                    input_path.as_ref().unwrap()
                ));
            }
        }
    };

    output_json(nmap_run, output_path, pretty);
}

fn output_json(nmap_run: nmap::NmapRun, output_path: &Option<String>, pretty: bool) {
    let json = if pretty {
        info!("Converting to pretty-printed JSON");
        match serde_json::to_string_pretty(&nmap_run) {
            Ok(j) => {
                debug!("Successfully converted to pretty JSON ({} bytes)", j.len());
                j
            }
            Err(e) => {
                fatal_error(&format!("Failed to convert to JSON: {}", e));
            }
        }
    } else {
        info!("Converting to compressed JSON");
        match serde_json::to_string(&nmap_run) {
            Ok(j) => {
                debug!(
                    "Successfully converted to compressed JSON ({} bytes)",
                    j.len()
                );
                j
            }
            Err(e) => {
                fatal_error(&format!("Failed to convert to JSON: {}", e));
            }
        }
    };

    match output_path {
        Some(path) => {
            info!("Writing JSON to file: {}", path);
            if let Err(e) = fs::write(path, &json) {
                fatal_error(&format!("Failed to write to file {}: {}", path, e));
            }
            info!("JSON written to file successfully");
        }
        None => {
            info!("Printing JSON to stdout");
            println!("{}", json);
        }
    }
}

fn process_xml_file(input_path: &str) -> nmap::NmapRun {
    let xml_content = match fs::read_to_string(input_path) {
        Ok(content) => {
            debug!("Successfully read {} bytes from file", content.len());
            content
        }
        Err(e) => {
            fatal_error(&format!("Failed to read file {}: {}", input_path, e));
        }
    };

    parse_xml_content(&xml_content)
}

fn process_xml_stdin() -> nmap::NmapRun {
    info!("Reading XML from stdin");
    let mut buffer = String::new();

    if let Err(e) = stdin().read_to_string(&mut buffer) {
        fatal_error(&format!("Failed to read from stdin: {}", e));
    }

    debug!("Successfully read {} bytes from stdin", buffer.len());
    parse_xml_content(&buffer)
}

fn parse_xml_content(content: &str) -> nmap::NmapRun {
    match nmap::parse_nmap_xml(content) {
        Ok(run) => {
            debug!("Successfully parsed Nmap XML data");
            run
        }
        Err(e) => {
            fatal_error(&format!("Failed to parse Nmap XML: {}", e));
        }
    }
}

fn process_gnmap_file(input_path: &str) -> nmap::NmapRun {
    let file = match std::fs::File::open(input_path) {
        Ok(file) => file,
        Err(e) => {
            fatal_error(&format!("Failed to open file {}: {}", input_path, e));
        }
    };

    parse_gnmap_content(file)
}

fn process_gnmap_stdin() -> nmap::NmapRun {
    info!("Reading gnmap from stdin");
    parse_gnmap_content(stdin())
}

fn parse_gnmap_content<R: io::Read>(reader: R) -> nmap::NmapRun {
    // Parse the gnmap content
    match nmap::gnmap::parse_gnmap(reader) {
        Ok(run) => {
            debug!("Successfully parsed gnmap data");
            run
        }
        Err(e) => {
            fatal_error(&format!("Failed to parse gnmap: {}", e));
        }
    }
}

fn generate_nmap_commands(
    input_path: &Option<String>,
    sort: bool,
    nmap_args: &str,
    single: bool,
    insert_target: &Option<String>,
) {
    debug!("Running nmap command generation");

    let (content, format) = if let Some(path) = input_path {
        if path == "-" {
            info!("Reading from stdin");
            match read_stdin_content() {
                Ok(content) => {
                    let format = detect_format_from_content(&content);
                    (content, format)
                }
                Err(e) => {
                    fatal_error(&format!("Failed to read from stdin: {}", e));
                }
            }
        } else {
            info!("Processing file: {}", path);
            let format = match detect_format(path) {
                Ok(f) => f,
                Err(e) => {
                    fatal_error(&format!("Error detecting file format: {}", e));
                }
            };

            match fs::read(path) {
                Ok(content) => (content, format),
                Err(e) => {
                    fatal_error(&format!("Failed to read file {}: {}", path, e));
                }
            }
        }
    } else {
        if stdin().is_terminal() {
            fatal_error("No input file specified and no data piped to stdin. Please provide an input file or pipe data to stdin.");
        }

        info!("Reading from stdin");
        match read_stdin_content() {
            Ok(content) => {
                let format = detect_format_from_content(&content);
                (content, format)
            }
            Err(e) => {
                fatal_error(&format!("Failed to read from stdin: {}", e));
            }
        }
    };

    let scan_data = match process_content_with_format(content, format) {
        Ok(data) => data,
        Err(e) => {
            fatal_error(&format!("Failed to process input: {}", e));
        }
    };

    if let Err(e) = process_nmap_results(&scan_data, sort, nmap_args, single, insert_target) {
        fatal_error(&format!("Failed to process nmap results: {}", e));
    }
}

fn process_nmap_results(
    scan_data: &nmap::NmapRun,
    sort: bool,
    nmap_args: &str,
    single: bool,
    insert_target: &Option<String>,
) -> Result<(), String> {
    debug!("Processing nmap results for command generation");

    if let Some(flag) = insert_target {
        if !flag.contains("{}") {
            return Err(
                "The --insert-target flag must contain a {} placeholder for the target".to_string(),
            );
        }
    }

    let mut ip_ports: HashMap<String, Vec<u16>> = HashMap::new();

    for host in &scan_data.hosts {
        if host.addresses.is_empty() {
            continue;
        }

        let ipv4_addr = host
            .addresses
            .iter()
            .find(|a| a.addrtype == nmap::AddressType::IPv4)
            .map(|a| a.addr.clone());

        let ip = match ipv4_addr {
            Some(ip) => ip,
            None => host.addresses[0].addr.clone(),
        };

        if let Some(ports_data) = &host.ports {
            if let Some(port_list) = &ports_data.ports {
                let ports = ip_ports.entry(ip).or_default();

                for port in port_list {
                    // Only include open ports
                    if port.state.state == nmap::PortState::Open {
                        ports.push(port.port_id as u16);
                    }
                }
            }
        }
    }

    for ports in ip_ports.values_mut() {
        ports.sort_unstable();
    }

    let mut ip_list: Vec<_> = ip_ports.into_iter().collect();

    if sort {
        debug!("Sorting output by IP address");
        ip_list.sort_by(|(a, _), (b, _)| a.cmp(b));
    }

    if single {
        let mut all_ports = std::collections::HashSet::new();
        for (_, ports) in &ip_list {
            all_ports.extend(ports.iter().copied());
        }
        let mut all_ports: Vec<_> = all_ports.into_iter().collect();
        all_ports.sort_unstable();

        let ports_str = all_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let ips_str = ip_list
            .iter()
            .map(|(ip, _)| ip.as_str())
            .collect::<Vec<_>>()
            .join(",");

        let mut cmd_parts = Vec::new();
        cmd_parts.push("nmap".to_string());

        if !nmap_args.is_empty() {
            cmd_parts.push(nmap_args.to_string());
        }

        if let Some(flag) = insert_target {
            let targets_combined = ip_list
                .iter()
                .map(|(ip, _)| ip.as_str())
                .collect::<Vec<_>>()
                .join("_");

            cmd_parts.push(flag.replace("{}", &targets_combined));
        }

        cmd_parts.push(format!("-p {}", ports_str));
        cmd_parts.push(ips_str);

        println!("{}", cmd_parts.join(" "));
    } else {
        for (ip, ports) in ip_list {
            if ports.is_empty() {
                continue;
            }

            let ports_str = ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");

            let mut cmd_parts = Vec::new();
            cmd_parts.push("nmap".to_string());

            if !nmap_args.is_empty() {
                cmd_parts.push(nmap_args.to_string());
            }

            if let Some(flag) = insert_target {
                cmd_parts.push(flag.replace("{}", &ip));
            }

            cmd_parts.push(format!("-p {}", ports_str));
            cmd_parts.push(ip);

            println!("{}", cmd_parts.join(" "));
        }
    }

    Ok(())
}
