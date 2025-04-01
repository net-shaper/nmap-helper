# nmap-rs Helper Tool

A Rust-based command-line utility for processing and working with Nmap output files. This tool helps you convert Nmap output formats and generate targeted Nmap commands from previous scan results.

## Features

- Convert Nmap output files between formats:
  - XML (-oX) to JSON
  - Greppable (-oG) to JSON
- Generate targeted Nmap commands from previous scan results
- Support for both single-target and multi-target command generation
- Automatic format detection
- Pretty or compressed JSON output
- Support for reading from files or stdin

## Installation

### From Source

1. Ensure you have Rust and Cargo installed (https://rustup.rs/)
2. Clone the repository
3. Build and install:
   ```bash
   make
   make install
   ```

### From Source Using Cargo
1. Ensure you have Rust and Cargo installed (https://rustup.rs/)
2. Clone the repository
3. Build and install:
   ```bash
   cargo build --release 
   cp target/release/nmap-helper /path/to/install/dir
   ```

## Usage

### Converting Nmap Output

Convert Nmap XML or greppable output to JSON:

```bash
# Convert from file
nmap-helper convert input.xml
nmap-helper convert input.gnmap

# Convert with pretty-printing
nmap-helper convert input.xml --pretty

# Convert to output file
nmap-helper convert input.xml -o output.json

# Read from stdin
cat input.xml | nmap-helper convert

# Force input format
nmap-helper convert input.txt --format json
```

### Generating Nmap Commands

Generate targeted Nmap commands from previous scan results:

```bash
# Basic usage
nmap-helper nmap input.xml

# Sort output by IP
nmap-helper nmap input.xml --sort

# Add additional Nmap arguments
nmap-helper nmap input.xml --nmap-args="-sV -sC"

# Generate a single command for all targets
nmap-helper nmap input.xml --single

# Insert targets into a custom flag
nmap-helper nmap input.xml --insert-target="-oA {}.results"
```

#### Command Generation Examples

1. Basic per-host commands:
   ```bash
   $ nmap-helper nmap scan.xml
   nmap -p 80,443 192.168.1.1
   nmap -p 22,80,443 192.168.1.2
   ```

2. Single command for all hosts:
   ```bash
   $ nmap-helper nmap scan.xml --single
   nmap -p 22,80,443 192.168.1.1,192.168.1.2
   ```

3. With additional Nmap arguments:
   ```bash
   $ nmap-helper nmap scan.xml --nmap-args="-sV -sC"
   nmap -sV -sC -p 80,443 192.168.1.1
   ```

4. With inserted targets:
   ```bash
   $ nmap-helper nmap scan.xml --insert-target="-oA {}.results"
   nmap -oA 192.168.1.1.results -p 80,443 192.168.1.1
   ```

## Command Reference

### Convert Subcommand

```
nmap-helper convert [OPTIONS] [INPUT]

Arguments:
  [INPUT]  Input Nmap file (XML or greppable format), omit to read from stdin

Options:
  -o, --output <FILE>   Output JSON file (defaults to stdout if not specified)
  -p, --pretty         Pretty-print the JSON output
  -f, --format <FORMAT> Force input format (xml or gnmap), otherwise auto-detected
  -h, --help          Print help
```

### Nmap Subcommand

```
nmap-helper nmap [OPTIONS] [INPUT]

Arguments:
  [INPUT]  Input Nmap file (XML or greppable format), omit to read from stdin

Options:
      --sort              Sort output by IP address
      --nmap-args <ARGS>  Additional nmap arguments to append to the command
      --single            Output a single nmap command for all IPs
      --insert-target <FLAG>  Add a flag with the target(s) inserted at {} placeholder
  -h, --help             Print help
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
