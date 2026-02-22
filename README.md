# Backend MCP Server

MCP server for backend development with architectural guidance, security analysis, Docker, and testing.

## Tools

| Tool | Description |
|------|-------------|
| `analyze_project` | Analyze structure, language, framework, Docker, database |
| `review_security` | Scan for hardcoded secrets, SQL injection, XSS, eval() risks |
| `analyze_api` | List all API endpoints with methods |
| `validate_api_structure` | Check REST best practices (versioning, health, auth) |
| `get_architecture_advice` | Architectural recommendations based on requirements |
| `scaffold_project` | Generate full project with Docker, tests, structure |
| `add_docker` | Add Docker config to existing project |
| `add_tests` | Add unit + integration tests |
| `execute_command`, `read_file`, `write_file`, `list_directory` | File/command operations |

## Usage

```bash
npm run dev    # Development
npm run build  # Production build
npm run start  # Run server
```

## Configure Claude Desktop

```json
{
  "mcpServers": {
    "backend": {
      "command": "npm",
      "args": ["run", "start"],
      "workdir": "/path/to/mcp-server"
    }
  }
}
```

## Examples

```
- "Scaffold a TypeScript project with Docker and tests"
- "Analyze the API structure"
- "Validate API follows REST best practices"
- "Add Docker to my project (has PostgreSQL)"
- "Review security of src/"
- "Architecture advice for a REST API with auth and PostgreSQL"
```
# backend-mcp
