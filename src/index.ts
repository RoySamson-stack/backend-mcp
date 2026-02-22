import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { $ } from "zx";
import fs from "fs/promises";
import path from "path";

const server = new Server(
  {
    name: "backend-mcp-server",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

interface ProjectAnalysis {
  language?: string;
  framework?: string;
  structure: string[];
  hasDocker: boolean;
  hasDb: boolean;
  hasAuth: boolean;
  securityIssues: string[];
}

async function analyzeProject(dir: string = "."): Promise<ProjectAnalysis> {
  const analysis: ProjectAnalysis = { 
    structure: [], 
    securityIssues: [],
    hasDocker: false,
    hasDb: false,
    hasAuth: false
  };
  
  try {
    const files = await fs.readdir(dir);
    analysis.structure = files;
    
    if (files.includes("package.json")) {
      const pkg = JSON.parse(await fs.readFile(path.join(dir, "package.json"), "utf-8"));
      analysis.language = "typescript";
      analysis.framework = Object.keys(pkg.dependencies || {}).find(d => 
        ["express", "fastify", "nest", "koa", "hono"].some(f => d.includes(f))
      );
    }
    if (files.includes("requirements.txt") || files.includes("pyproject.toml")) {
      analysis.language = "python";
    }
    if (files.includes("Cargo.toml")) analysis.language = "rust";
    if (files.includes("go.mod")) analysis.language = "go";
    
    analysis.hasDocker = files.includes("Dockerfile") || files.includes("docker-compose.yml");
    analysis.hasDb = files.some(f => f.includes("database") || f.includes("db"));
    analysis.hasAuth = files.some(f => f.includes("auth") || f.includes("middleware"));
    
    for (const file of files) {
      if (file.endsWith(".env")) {
        analysis.securityIssues.push(`Exposed .env file: ${file}`);
      }
    }
  } catch (e) {}
  
  return analysis;
}

function suggestArchitecture(analysis: ProjectAnalysis, requirements: string): string {
  const suggestions: string[] = [];
  
  if (requirements.includes("api") || requirements.includes("rest")) {
    suggestions.push("REST API: Use /api/v1/ versioning, proper HTTP methods, status codes");
  }
  if (requirements.includes("graphql")) {
    suggestions.push("GraphQL: Define schema, resolvers, use DataLoader for N+1");
  }
  if (requirements.includes("auth") || requirements.includes("login")) {
    suggestions.push(`
SECURITY AUTH:
  - JWT: short-lived access (15-60min) + refresh tokens
  - Store refresh in httpOnly, secure cookies
  - CSRF protection, rate limit auth endpoints
  - Password: bcrypt/argon2 hashing, salt
  - MFA support (TOTP)
`);
  }
  if (requirements.includes("database") || requirements.includes("data")) {
    suggestions.push(`
DATABASE:
  - Connection pooling (PgBouncer if needed)
  - Migrations: Prisma/Alembic/Flyway
  - Index frequently queried columns
  - Use transactions for multi-step ops
  - Read replicas for heavy read loads
`);
  }
  if (requirements.includes("microservice")) {
    suggestions.push(`
MICROSERVICE:
  - API Gateway / Service mesh
  - Message queue: RabbitMQ/Kafka
  - Distributed tracing: Jaeger
  - Health checks per service
  - Circuit breaker pattern
`);
  }
  suggestions.push(`
SECURITY:
  - Input: Zod/Joi/class-validator
  - Output: escape HTML, prevent XSS
  - SQL: parameterized queries only
  - Headers: helmet.js
  - CORS: explicit origins only
  - Rate limiting per IP/user
  - Audit logging
  - Generic error messages
`);
  
  return suggestions.join("\n");
}

function analyzeCodeSecurity(filePath: string, content: string): string[] {
  const issues: string[] = [];
  
  if (/password\s*=\s*['"][^'"]+['"]/i.test(content) && !content.includes("process.env")) {
    issues.push(`${filePath}: Hardcoded password - use env vars`);
  }
  if (/api[_-]?key\s*=\s*['"][^'"]+['"]/i.test(content)) {
    issues.push(`${filePath}: Hardcoded API key - use env vars`);
  }
  if (/SELECT.*FROM.*\+\s*['"]/i.test(content) || /"\s*\+\s*req/i.test(content)) {
    issues.push(`${filePath}: SQL/Query injection risk`);
  }
  if (/eval\s*\(/.test(content)) {
    issues.push(`${filePath}: Dangerous eval() - code injection risk`);
  }
  if (/innerHTML\s*=/.test(content)) {
    issues.push(`${filePath}: XSS risk - use textContent`);
  }
  if (!content.includes("HttpOnly") && content.includes("token")) {
    issues.push(`${filePath}: Token may not be secure`);
  }
  
  return issues;
}

interface APIEndpoint {
  method: string;
  path: string;
  handler: string;
}

function analyzeAPI(filePath: string, content: string): APIEndpoint[] {
  const endpoints: APIEndpoint[] = [];
  
  const routeRegex = /(?:app|router|Route)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
  let match;
  while ((match = routeRegex.exec(content)) !== null) {
    endpoints.push({
      method: match[1].toUpperCase(),
      path: match[2],
      handler: filePath
    });
  }
  
  return endpoints;
}

function generateDockerConfig(framework: string, hasDb: boolean, language: string): Record<string, string> {
  const files: Record<string, string> = {};
  
  if (language === "typescript" || language === "node") {
    files["Dockerfile"] = `FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Build
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build || true

# Production
FROM node:20-alpine
WORKDIR /app

COPY --from=0 /app/node_modules ./node_modules
COPY --from=0 /app/dist ./dist
COPY --from=0 /app/package*.json ./

ENV NODE_ENV=production
EXPOSE 3000

USER node
CMD ["node", "dist/index.js"]
`;

    files[".dockerignore"] = `node_modules
npm-debug.log
dist
.git
.env
*.test.ts
coverage
.DS_Store
`;
  }

  if (language === "python") {
    files["Dockerfile"] = `FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
`;
  }

  if (language === "go") {
    files["Dockerfile"] = `FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app .

FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app .

EXPOSE 8080
CMD ["./app"]
`;
  }

  const compose: any = {
    version: "3.8",
    services: {
      app: {
        build: ".",
        ports: ["3000:3000"],
        environment: ["NODE_ENV=production"],
        restart: "unless-stopped",
        healthcheck: {
          test: ["CMD", "wget", "-q", "--spider", "http://localhost:3000/health"],
          interval: "30s",
          timeout: "10s",
          retries: 3
        }
      }
    }
  };

  if (hasDb) {
    compose.services.db = {
      image: "postgres:15-alpine",
      environment: {
        POSTGRES_USER: "${DB_USER:-app}",
        POSTGRES_PASSWORD: "${DB_PASSWORD:-changeme}",
        POSTGRES_DB: "${DB_NAME:-app}"
      },
      volumes: ["postgres_data:/var/lib/postgresql/data"],
      healthcheck: {
        test: ["CMD-SHELL", "pg_isready -U ${DB_USER:-app}"],
        interval: "10s",
        timeout: "5s",
        retries: 5
      }
    };
    compose.services.app.depends_on = {
      db: { condition: "service_healthy" }
    };
    compose.services.app.environment.push("DATABASE_URL=postgres://${DB_USER:-app}:${DB_PASSWORD:-changeme}@db:5432/${DB_NAME:-app}");
    compose.volumes = { postgres_data: null };
  }

  files["docker-compose.yml"] = JSON.stringify(compose, null, 2);

  files["docker-compose.dev.yml"] = JSON.stringify({
    version: "3.8",
    services: {
      app: {
        build: { context: ".", target: "builder" },
        volumes: ["./src:/app/src"],
        command: "npm run dev",
        environment: ["NODE_ENV=development"],
        ports: ["3000:3000"]
      },
      ...(hasDb ? {
        db: {
          image: "postgres:15-alpine",
          environment: {
            POSTGRES_USER: "dev",
            POSTGRES_PASSWORD: "dev",
            POSTGRES_DB: "dev"
          },
          ports: ["5432:5432"],
          volumes: ["dev_data:/var/lib/postgresql/data"]
        }
      } : {})
    },
    volumes: { dev_data: null }
  }, null, 2);

  return files;
}

function generateUnitTests(framework: string, language: string): Record<string, string> {
  const files: Record<string, string> = {};
  
  if (language === "typescript") {
    files["vitest.config.ts"] = `import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    environment: 'node',
    globals: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: ['**/node_modules/**', '**/dist/**', '**/*.test.ts']
    },
    include: ['src/**/*.test.ts'],
    setupFiles: ['./test/setup.ts']
  }
});
`;

    files["test/setup.ts"] = `import { beforeAll, afterAll, afterEach, vi } from 'vitest';

beforeAll(() => {
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = 'test-secret';
});

afterEach(() => {
  vi.clearAllMocks();
});

afterAll(() => {
  vi.resetAllMocks();
});
`;

    files["test/utils.ts"] = `import { expect, describe, it, beforeEach } from 'vitest';

export * from './setup';

export function createMockRequest(overrides = {}) {
  return {
    body: {},
    params: {},
    query: {},
    headers: {},
    ...overrides
  };
}

export function createMockResponse() {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  res.send = vi.fn().mockReturnValue(res);
  return res;
}

export function expectSuccess(res: any, status = 200) {
  expect(res.status).toHaveBeenCalledWith(status);
}

export function expectError(res: any, status = 400) {
  expect(res.status).toHaveBeenCalledWith(status);
}
`;

    files["src/index.test.ts"] = `import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import app from '../src/index.js';

describe('Health Check', () => {
  it('GET /health should return 200', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('status', 'ok');
  });
});

describe('API Endpoints', () => {
  describe('GET /api/v1/health', () => {
    it('should return health status', async () => {
      const res = await request(app).get('/api/v1/health');
      expect(res.status).toBe(200);
    });
  });
});
`;
  }

  if (language === "python") {
    files["pytest.ini"] = `[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
`;

    files["tests/conftest.py"] = `import pytest
from fastapi.testclient import TestClient
from main import app

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def auth_headers(client):
    response = client.post("/auth/login", json={"email": "test@test.com", "password": "testpass"})
    token = response.json().get("access_token")
    return {"Authorization": f"Bearer {token}"}
`;

    files["tests/test_health.py"] = `import pytest

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
`;
  }

  return files;
}

function generateIntegrationTests(framework: string, hasDb: boolean, language: string): Record<string, string> {
  const files: Record<string, string> = {};
  
  if (language === "typescript") {
    files["test/integration/setup.ts"] = `import { beforeAll, afterAll } from 'vitest';

const TEST_DB = 'postgresql://test:test@localhost:5432/test_db';

beforeAll(async () => {
  // Setup test database
});

afterAll(async () => {
  // Cleanup
});
`;

    files["test/integration/api.test.ts"] = `import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import app from '../../src/index.js';

describe('API Integration Tests', () => {
  const baseURL = '/api/v1';

  describe('Health Endpoint', () => {
    it('should return 200 with correct structure', async () => {
      const res = await request(app).get(\`\${baseURL}/health\`);
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ status: 'ok' });
    });
  });

  describe('Auth Endpoints', () => {
    it('POST /auth/register should create user', async () => {
      const res = await request(app)
        .post(\`\${baseURL}/auth/register\`)
        .send({ email: 'new@test.com', password: 'password123' });
      expect(res.status).toBe(201);
    });

    it('POST /auth/login should return token', async () => {
      const res = await request(app)
        .post(\`\${baseURL}/auth/login\`)
        .send({ email: 'test@test.com', password: 'password123' });
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('access_token');
    });

    it('should reject invalid credentials', async () => {
      const res = await request(app)
        .post(\`\${baseURL}/auth/login\`)
        .send({ email: 'test@test.com', password: 'wrongpass' });
      expect(res.status).toBe(401);
    });
  });

  describe('Protected Endpoints', () => {
    let token: string;

    beforeAll(async () => {
      const res = await request(app)
        .post(\`\${baseURL}/auth/login\`)
        .send({ email: 'test@test.com', password: 'password123' });
      token = res.body.access_token;
    });

    it('should require authentication', async () => {
      const res = await request(app).get(\`\${baseURL}/users/me\`);
      expect(res.status).toBe(401);
    });

    it('should access with valid token', async () => {
      const res = await request(app)
        .get(\`\${baseURL}/users/me\`)
        .set('Authorization', \`Bearer \${token}\`);
      expect(res.status).toBe(200);
    });
  });

  describe('Validation', () => {
    it('should reject invalid email', async () => {
      const res = await request(app)
        .post(\`\${baseURL}/auth/register\`)
        .send({ email: 'invalid-email', password: 'pass123' });
      expect(res.status).toBe(400);
    });

    it('should reject weak password', async () => {
      const res = await request(app)
        .post(\`\${baseURL}/auth/register\`)
        .send({ email: 'test@test.com', password: '123' });
      expect(res.status).toBe(400);
    });
  });

  describe('Rate Limiting', () => {
    it('should throttle excessive requests', async () => {
      const promises = Array(101).fill(null).map(() => 
        request(app).get(\`\${baseURL}/health\`)
      );
      const results = await Promise.all(promises);
      const tooMany = results.filter(r => r.status === 429);
      expect(tooMany.length).toBeGreaterThan(0);
    });
  });
});
`;

    if (hasDb) {
      files["test/integration/database.test.ts"] = `import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../src/index.js';

describe('Database Integration Tests', () => {
  describe('CRUD Operations', () => {
    let testId: string;

    it('POST /items should create item', async () => {
      const res = await request(app)
        .post('/api/v1/items')
        .send({ name: 'Test Item', description: 'Test' });
      expect(res.status).toBe(201);
      testId = res.body.id;
    });

    it('GET /items/:id should return item', async () => {
      const res = await request(app).get(\`/api/v1/items/\${testId}\`);
      expect(res.status).toBe(200);
      expect(res.body.name).toBe('Test Item');
    });

    it('PUT /items/:id should update item', async () => {
      const res = await request(app)
        .put(\`/api/v1/items/\${testId}\`)
        .send({ name: 'Updated Item' });
      expect(res.status).toBe(200);
    });

    it('DELETE /items/:id should remove item', async () => {
      const res = await request(app).delete(\`/api/v1/items/\${testId}\`);
      expect(res.status).toBe(204);
    });

    it('should return 404 for non-existent item', async () => {
      const res = await request(app).get('/api/v1/items/nonexistent-id');
      expect(res.status).toBe(404);
    });
  });

  describe('Transactions', () => {
    it('should rollback on failure', async () => {
      const initialCount = await getItemCount();
      try {
        await request(app).post('/api/v1/items/bulk').send({ items: [{ name: 'a' }, { name: 'b' }] });
      } catch {}
      const finalCount = await getItemCount();
      expect(finalCount).toBe(initialCount);
    });
  });
});

async function getItemCount(): Promise<number> {
  const res = await request(app).get('/api/v1/items');
  return res.body.length;
}
`;
    }
  }

  if (language === "python") {
    files["tests/integration/test_api.py"] = `import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200

def test_create_user():
    response = client.post("/users", json={"email": "test@test.com", "password": "pass123"})
    assert response.status_code == 201

def test_login():
    response = client.post("/auth/login", json={"email": "test@test.com", "password": "pass123"})
    assert response.status_code == 200
    assert "access_token" in response.json()

@pytest.mark.parametrize("email,status", [
    ("invalid", 400),
    ("test@test.com", 200),
])
def test_email_validation(email, status):
    response = client.post("/users", json={"email": email, "password": "pass123"})
    assert response.status_code == status
`;
  }

  return files;
}

function generateProjectScaffold(language: string, requirements: string): Record<string, string> {
  const files: Record<string, string> = {};
  
  if (language === "typescript") {
    files["package.json"] = JSON.stringify({
      name: "backend-project",
      version: "1.0.0",
      type: "module",
      scripts: {
        "dev": "tsx watch src/index.ts",
        "build": "tsc",
        "start": "node dist/index.js",
        "lint": "eslint src --ext .ts",
        "test": "vitest",
        "test:run": "vitest run",
        "test:coverage": "vitest run --coverage"
      },
      dependencies: {
        "express": "^4.18.0",
        "zod": "^3.22.0",
        "dotenv": "^16.0.0",
        "cors": "^2.8.5",
        "helmet": "^7.0.0"
      },
      devDependencies: {
        "@types/node": "^20.0.0",
        "@types/express": "^4.17.0",
        "@types/cors": "^2.8.0",
        "typescript": "^5.0.0",
        "tsx": "^4.0.0",
        "eslint": "^8.0.0",
        "vitest": "^1.0.0",
        "supertest": "^6.3.0",
        "@types/supertest": "^6.0.0",
        "vite-tsconfig-paths": "^4.0.0"
      }
    }, null, 2);
    
    files["tsconfig.json"] = JSON.stringify({
      compilerOptions: {
        target: "ES2022",
        module: "ESNext",
        moduleResolution: "bundler",
        strict: true,
        esModuleInterop: true,
        skipLibCheck: true,
        outDir: "dist",
        rootDir: "src",
        resolveJsonModule: true,
        paths: { "@/*": ["./src/*"] }
      },
      include: ["src/**/*"],
      exclude: ["node_modules", "dist", "test"]
    }, null, 2);
    
    files["src/index.ts"] = `import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config } from 'dotenv';

config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));
app.use(express.json());

// Routes
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/v1/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0' });
});

app.listen(PORT, () => {
  console.log(\`Server running on port \${PORT}\`);
});

export default app;
`;
    
    files["src/routes/index.ts"] = `import { Router } from 'express';
const router = Router();

router.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

export default router;
`;

    files["src/middleware/errorHandler.ts"] = `import { Request, Response, NextFunction } from 'express';

export function errorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  console.error(err.stack);
  
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
}
`;

    files["src/middleware/validate.ts"] = `import { z } from 'zod';

export const createUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
  name: z.string().min(1).optional()
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string()
});

export function validate(schema: z.ZodSchema) {
  return (req: any, res: any, next: any) => {
    try {
      schema.parse(req.body);
      next();
    } catch (error) {
      res.status(400).json({ error: 'Validation failed', details: error });
    }
  };
}
`;
    
    files[".env.example"] = `PORT=3000
NODE_ENV=development
DATABASE_URL=postgresql://user:pass@localhost:5432/db
JWT_SECRET=your-secret-key-here
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
`;
    
    files[".gitignore"] = `node_modules/
dist/
.env
*.log
coverage/
.DS_Store
*.tgz
`;
  }
  
  if (requirements.includes("docker") || requirements.includes("container")) {
    Object.assign(files, generateDockerConfig("express", requirements.includes("database"), language));
  }
  
  if (requirements.includes("test")) {
    Object.assign(files, generateUnitTests("express", language));
    Object.assign(files, generateIntegrationTests("express", requirements.includes("database"), language));
  }
  
  return files;
}

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "analyze_project",
        description: "Analyze project structure and provide architectural feedback",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string", description: "Project directory path" },
          },
        },
      },
      {
        name: "review_security",
        description: "Review code for security vulnerabilities",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string", description: "File or directory to review" },
          },
          required: ["path"],
        },
      },
      {
        name: "analyze_api",
        description: "Analyze API endpoints in the project",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string", description: "Directory to scan" },
          },
        },
      },
      {
        name: "validate_api_structure",
        description: "Validate API follows REST best practices",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string", description: "Path to API files" },
          },
        },
      },
      {
        name: "get_architecture_advice",
        description: "Get architectural advice based on requirements",
        inputSchema: {
          type: "object",
          properties: {
            requirements: { type: "string" },
            language: { type: "string" },
          },
          required: ["requirements"],
        },
      },
      {
        name: "scaffold_project",
        description: "Generate project scaffold with Docker and tests",
        inputSchema: {
          type: "object",
          properties: {
            requirements: { type: "string" },
            language: { type: "string" },
            outputDir: { type: "string" },
          },
          required: ["requirements", "language"],
        },
      },
      {
        name: "add_docker",
        description: "Add Docker configuration to existing project",
        inputSchema: {
          type: "object",
          properties: {
            framework: { type: "string" },
            hasDb: { type: "boolean" },
            language: { type: "string" },
          },
        },
      },
      {
        name: "add_tests",
        description: "Add unit and integration tests",
        inputSchema: {
          type: "object",
          properties: {
            framework: { type: "string" },
            language: { type: "string" },
            hasDb: { type: "boolean" },
          },
        },
      },
      {
        name: "execute_command",
        description: "Execute a shell command",
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string" },
            cwd: { type: "string" },
          },
          required: ["command"],
        },
      },
      {
        name: "read_file",
        description: "Read a file",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string" },
          },
          required: ["path"],
        },
      },
      {
        name: "write_file",
        description: "Write content to a file",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string" },
            content: { type: "string" },
          },
          required: ["path", "content"],
        },
      },
      {
        name: "list_directory",
        description: "List directory contents",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string" },
          },
          required: ["path"],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "analyze_project": {
        const analysis = await analyzeProject(args?.path as string || ".");
        let report = `## Project Analysis\n\n`;
        report += `**Language:** ${analysis.language || "Unknown"}\n`;
        report += `**Framework:** ${analysis.framework || "Not detected"}\n`;
        report += `**Has Docker:** ${analysis.hasDocker ? "Yes" : "No"}\n`;
        report += `**Has Database:** ${analysis.hasDb ? "Yes" : "No"}\n`;
        report += `**Has Auth:** ${analysis.hasAuth ? "Yes" : "No"}\n\n`;
        report += `### Structure\n${analysis.structure.join("\n")}\n\n`;
        
        if (analysis.securityIssues.length > 0) {
          report += `### Security Issues\n${analysis.securityIssues.map(i => `- ${i}`).join("\n")}\n`;
        }
        
        return { content: [{ type: "text", text: report }] };
      }

      case "review_security": {
        const targetPath = args?.path as string;
        const stats = await fs.stat(targetPath);
        const issues: string[] = [];
        
        if (stats.isDirectory()) {
          const files = await fs.readdir(targetPath);
          for (const file of files) {
            if (file.endsWith(".ts") || file.endsWith(".js") || file.endsWith(".py")) {
              const content = await fs.readFile(path.join(targetPath, file), "utf-8");
              issues.push(...analyzeCodeSecurity(file, content));
            }
          }
        } else {
          const content = await fs.readFile(targetPath, "utf-8");
          issues.push(...analyzeCodeSecurity(targetPath, content));
        }
        
        const report = issues.length > 0 
          ? `## Security Review\n\n${issues.map(i => `- ${i}`).join("\n")}`
          : `## Security Review\n\nNo issues found.`;
        
        return { content: [{ type: "text", text: report }] };
      }

      case "analyze_api": {
        const targetPath = args?.path as string || "src";
        const endpoints: APIEndpoint[] = [];
        
        const scanDir = async (dir: string) => {
          try {
            const entries = await fs.readdir(dir, { withFileTypes: true });
            for (const entry of entries) {
              const fullPath = path.join(dir, entry.name);
              if (entry.isDirectory()) {
                await scanDir(fullPath);
              } else if (entry.name.endsWith(".ts") || entry.name.endsWith(".js")) {
                const content = await fs.readFile(fullPath, "utf-8");
                endpoints.push(...analyzeAPI(fullPath, content));
              }
            }
          } catch {}
        };
        
        await scanDir(targetPath);
        
        let report = `## API Endpoints (${endpoints.length} found)\n\n`;
        const byMethod: Record<string, APIEndpoint[]> = {};
        for (const ep of endpoints) {
          if (!byMethod[ep.method]) byMethod[ep.method] = [];
          byMethod[ep.method].push(ep);
        }
        
        for (const [method, eps] of Object.entries(byMethod)) {
          report += `### ${method}\n`;
          for (const ep of eps) {
            report += `- \`${ep.path}\` (${ep.handler})\n`;
          }
          report += "\n";
        }
        
        return { content: [{ type: "text", text: report }] };
      }

      case "validate_api_structure": {
        const targetPath = args?.path as string || "src";
        const endpoints: APIEndpoint[] = [];
        
        const scanDir = async (dir: string) => {
          try {
            const entries = await fs.readdir(dir, { withFileTypes: true });
            for (const entry of entries) {
              const fullPath = path.join(dir, entry.name);
              if (entry.isDirectory()) {
                await scanDir(fullPath);
              } else if (entry.name.endsWith(".ts") || entry.name.endsWith(".js")) {
                const content = await fs.readFile(fullPath, "utf-8");
                endpoints.push(...analyzeAPI(fullPath, content));
              }
            }
          } catch {}
        };
        
        await scanDir(targetPath);
        
        let report = `## API Structure Validation\n\n`;
        const issues: string[] = [];
        const passed: string[] = [];
        
        if (endpoints.length === 0) {
          issues.push("No API endpoints found");
        }
        
        const hasHealth = endpoints.some(e => e.path.includes("health"));
        if (!hasHealth) issues.push("Missing health check endpoint");
        else passed.push("Health check endpoint present");
        
        const hasVersioning = endpoints.some(e => e.path.includes("/v1/"));
        if (!hasVersioning) issues.push("No API versioning detected (/v1/)");
        else passed.push("API versioning present");
        
        const hasAuth = endpoints.some(e => e.path.includes("auth"));
        if (!hasAuth) issues.push("No auth endpoints found");
        
        const getNoBody = endpoints.filter(e => ["GET", "DELETE"].includes(e.method) && e.path.includes("body"));
        if (getNoBody.length > 0) issues.push("GET/DELETE should not have request body");
        
        report += `### Issues (${issues.length})\n${issues.map(i => `- ${i}`).join("\n")}\n\n`;
        report += `### Passed (${passed.length})\n${passed.map(p => `- ${p}`).join("\n")}\n`;
        
        report += `\n### Recommendations\n`;
        if (!hasVersioning) {
          report += `- Add API versioning: /api/v1/endpoint\n`;
        }
        report += `- Add rate limiting middleware\n`;
        report += `- Add request validation (Zod/Joi)\n`;
        
        return { content: [{ type: "text", text: report }] };
      }

      case "get_architecture_advice": {
        const analysis = await analyzeProject(".");
        const advice = suggestArchitecture(analysis, args?.requirements as string);
        
        let report = `## Architecture Advice\n\n`;
        report += `Based on: "${args?.requirements}"\n\n`;
        report += advice;
        
        return { content: [{ type: "text", text: report }] };
      }

      case "scaffold_project": {
        const files = generateProjectScaffold(
          args?.language as string || "typescript",
          args?.requirements as string
        );
        
        const outputDir = args?.outputDir as string || ".";
        const createdFiles: string[] = [];
        
        for (const [filePath, content] of Object.entries(files)) {
          const fullPath = path.join(outputDir, filePath);
          await fs.mkdir(path.dirname(fullPath), { recursive: true });
          await fs.writeFile(fullPath, content);
          createdFiles.push(filePath);
        }
        
        return { content: [{ type: "text", text: `## Generated Project Scaffold\n\nCreated ${createdFiles.length} files:\n${createdFiles.map(f => `- ${f}`).join("\n")}\n\nRun \`npm install && npm run dev\` to start.` }] };
      }

      case "add_docker": {
        const files = generateDockerConfig(
          args?.framework as string || "express",
          args?.hasDb as boolean || false,
          args?.language as string || "typescript"
        );
        
        const createdFiles: string[] = [];
        for (const [filePath, content] of Object.entries(files)) {
          await fs.writeFile(filePath, content);
          createdFiles.push(filePath);
        }
        
        return { content: [{ type: "text", text: `## Docker Configuration Added\n\nCreated:\n${createdFiles.map(f => `- ${f}`).join("\n")}\n\nRun \`docker-compose up\` to start.` }] };
      }

      case "add_tests": {
        const files = {
          ...generateUnitTests(args?.framework as string || "express", args?.language as string || "typescript"),
          ...generateIntegrationTests(args?.framework as string || "express", args?.hasDb as boolean || false, args?.language as string || "typescript")
        };
        
        const createdFiles: string[] = [];
        for (const [filePath, content] of Object.entries(files)) {
          await fs.mkdir(path.dirname(filePath), { recursive: true });
          await fs.writeFile(filePath, content);
          createdFiles.push(filePath);
        }
        
        return { content: [{ type: "text", text: `## Tests Added\n\nCreated:\n${createdFiles.map(f => `- ${f}`).join("\n")}\n\nRun \`npm test\` to execute.` }] };
      }

      case "execute_command": {
        const cwd = args?.cwd as string | undefined || process.cwd();
        const result = await $({ cwd })`${args?.command}`;
        return { content: [{ type: "text", text: result.stdout || result.stderr }] };
      }

      case "read_file": {
        const content = await fs.readFile(args?.path as string, "utf-8");
        return { content: [{ type: "text", text: content }] };
      }

      case "write_file": {
        const filePath = args?.path as string;
        await fs.mkdir(path.dirname(filePath), { recursive: true });
        await fs.writeFile(filePath, args?.content as string);
        return { content: [{ type: "text", text: `Written: ${filePath}` }] };
      }

      case "list_directory": {
        const entries = await fs.readdir(args?.path as string, { withFileTypes: true });
        const result = entries.map(e => `${e.isDirectory() ? "d" : "-" } ${e.name}`).join("\n");
        return { content: [{ type: "text", text: result }] };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error: any) {
    return {
      content: [{ type: "text", text: `Error: ${error.message}` }],
      isError: true,
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
