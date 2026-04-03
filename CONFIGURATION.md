# Impulse Server - External Configuration Guide

## Overview

The server can be configured through multiple external sources without modifying the code:

1. **Configuration File** (JSON)
2. **Environment Variables**
3. **CLI Arguments**
4. **HTTP API** (runtime configuration)

## Configuration Priority

The configuration is loaded with the following priority (highest to lowest):
1. CLI arguments
2. Environment variables
3. Configuration file
4. Default values

## 1. Configuration File

Create a `config.json` file in the project root:

```json
{
  "server": {
    "address": "0.0.0.0:8080",
    "password": "your_secure_password_here"
  },
  "api": {
    "enabled": true,
    "address": "0.0.0.0:3000"
  }
}
```

Use a custom config file path:
```bash
cargo run -- --config /path/to/your/config.json
```

## 2. Environment Variables

Copy `.env.example` to `.env` and modify as needed:

```bash
cp .env.example .env
```

Environment variables (prefix: `IMPULSE_`):
- `IMPULSE_SERVER__ADDRESS` - WebSocket server address
- `IMPULSE_SERVER__PASSWORD` - Server password
- `IMPULSE_API__ENABLED` - Enable configuration API
- `IMPULSE_API__ADDRESS` - Configuration API address

## 3. CLI Arguments

```bash
# Show help
cargo run -- --help

# Set server address
cargo run -- --address 127.0.0.1:9090

# Set password
cargo run -- --password my_secret_password

# Enable configuration API
cargo run -- --enable-config-api

# Custom config file
cargo run -- --config custom-config.json

# Combined options
cargo run -- --address 0.0.0.0:8080 --password secret --enable-config-api
```

### CLI Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--address` | `-a` | Server listen address | 0.0.0.0:8080 |
| `--password` | `-p` | Server password | your_secure_password_here |
| `--config` | `-c` | Config file path | config.json |
| `--enable-config-api` | - | Enable HTTP config API | false |
| `--api-address` | - | API listen address | 0.0.0.0:3000 |

## 4. HTTP Configuration API

When enabled, the server exposes endpoints for runtime configuration changes.

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/config` | Get full configuration |
| GET | `/config/server` | Get server settings |
| PUT | `/config/server` | Update server settings |
| GET | `/config/api` | Get API settings |
| PUT | `/config/api` | Update API settings |
| POST | `/config/password` | Update password only |
| GET | `/health` | Health check |

### Examples

```bash
# Get current configuration
curl http://localhost:3000/config

# Update server address
curl -X PUT http://localhost:3000/config/server \
  -H "Content-Type: application/json" \
  -d '{"address": "0.0.0.0:9090"}'

# Update password
curl -X POST http://localhost:3000/config/password \
  -H "Content-Type: application/json" \
  -d '{"password": "new_password"}'

# Update both address and password
curl -X PUT http://localhost:3000/config/server \
  -H "Content-Type: application/json" \
  -d '{"address": "0.0.0.0:9090", "password": "new_password"}'

# Health check
curl http://localhost:3000/health
```

## Quick Start

### Using config file
```bash
# Copy example config
cp config.example.json config.json
# Edit config.json as needed
cargo run
```

### Using environment variables
```bash
# Copy example .env
cp .env.example .env
# Edit .env as needed
cargo run
```

### Using CLI arguments
```bash
cargo run -- -a 0.0.0.0:8080 -p mypassword --enable-config-api
```
