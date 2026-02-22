# MCP RE Server

MCP server for Reverse Engineering & Binary Analysis with backend development tools.

## Features

### Reverse Engineering Tools
| Tool | Description |
|------|-------------|
| `ghidra_analyze` | Analyze binary with Ghidra (headless mode) |
| `ghidra_decompile` | Decompile binary functions with Ghidra |
| `yara_scan` | Scan files with YARA rules for malware indicators |
| `analyze_binary` | Static analysis - extract strings, checksec, binary info |
| `radare2_analyze` | Analyze with Radare2 (functions, imports, strings) |
| `pestudio_analyze` | Analyze PE (Windows) files |
| `dynamic_analysis` | Behavioral analysis on suspicious files |
| `network_analysis` | Analyze pcap files for IOCs |
| `memory_forensics` | Memory dump analysis with Volatility commands |
| `gdb_debug` | Debug binaries with GDB |

### Backend Development Tools
| Tool | Description |
|------|-------------|
| `analyze_project` | Analyze project structure, language, framework |
| `review_security` | Scan for hardcoded secrets, SQL injection, XSS |
| `analyze_api` | List all API endpoints |
| `validate_api_structure` | Check REST best practices |
| `get_architecture_advice` | Architectural recommendations |
| `scaffold_project` | Generate project with Docker & tests |
| `add_docker` | Add Docker configuration |
| `add_tests` | Add unit & integration tests |
| `execute_command`, `read_file`, `write_file`, `list_directory` | File operations |

## Quick Start

```bash
npm install
npm run server
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GHIDRA_PATH` | Ghidra installation path | `/opt/ghidra` |
| `YARA_RULES_PATH` | Custom YARA rules directory | `./rules` |

## Usage Examples

```
- "Analyze binary /path/to/binary with Ghidra"
- "Scan malware.exe with YARA rules"
- "Run dynamic analysis on suspicious file"
- "Analyze network capture traffic.pcap"
- "Decompile main function from binary"
- "Check security of my binary (checksec)"
- "Analyze memory dump memory.dmp"
- "Debug binary with GDB at main"
- "Analyze PE file with PE Studio"
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "mcp-re": {
      "command": "npm",
      "args": ["run", "server"],
      "workdir": "/path/to/mcp"
    }
  }
}
```

## Requirements

### RE Tools (optional)
- Ghidra - Binary analysis & decompilation
- YARA - Malware scanning
- Radare2 - Binary analysis
- checksec - Binary security checks
- strings - String extraction
- Volatility - Memory forensics
- tshark - Network analysis
- GDB - Debugging

Install on Kali/RE Linux:
```bash
sudo apt install yara radare2 checksec binutils volatility tshark gdb
```
