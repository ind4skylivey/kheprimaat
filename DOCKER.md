# Docker Deployment Guide

This guide covers how to deploy KhepriMaat using Docker and Docker Compose.

## Quick Start

### Using Docker Compose (Recommended)

1. **Clone the repository**:
```bash
git clone https://github.com/ind4skylivey/kheprimaat.git
cd kheprimaat
```

2. **Start the service**:
```bash
docker-compose up -d
```

3. **Check status**:
```bash
docker-compose ps
docker-compose logs -f
```

4. **Access the API**:
```bash
curl http://localhost:3000/metrics
```

That's it! KhepriMaat is now running with all tools pre-installed.

## Using Docker Directly

### Build the image

```bash
docker build -t kheprimaat:latest .
```

### Run the container

```bash
docker run -d \
  --name kheprimaat \
  -p 3000:3000 \
  -v $(pwd)/data:/data \
  -e DATABASE_PATH=/data/kheprimaat.db \
  -e RUST_LOG=info \
  kheprimaat:latest
```

## Configuration

### Environment Variables

Configure KhepriMaat via environment variables in `docker-compose.yml`:

```yaml
environment:
  # Database
  - DATABASE_PATH=/data/kheprimaat.db
  
  # API
  - CONTROL_API_HOST=0.0.0.0
  - CONTROL_API_PORT=3000
  
  # Logging
  - RUST_LOG=info  # debug, info, warn, error
  
  # SMTP Notifications
  - SMTP_HOST=smtp.gmail.com
  - SMTP_PORT=587
  - SMTP_USERNAME=your-email@gmail.com
  - SMTP_PASSWORD=your-app-password
  
  # Slack
  - SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
  
  # Discord
  - DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
  
  # Generic Webhook
  - WEBHOOK_URL=https://your-endpoint.com/webhook
```

### Volumes

The following volumes are mounted:

| Host Path | Container Path | Purpose |
|-----------|----------------|---------|
| `./data` | `/data` | Database persistence |
| `./templates` | `/app/templates` | Custom scan configs |
| `./logs` | `/app/logs` | Application logs (optional) |

### Ports

| Port | Description |
|------|-------------|
| 3000 | Control API (HTTP) |

## Pre-installed Tools

The Docker image includes all required security tools:

- **Subfinder** v2.6.3 - Subdomain enumeration
- **Nuclei** v3.1.5 - Vulnerability scanner
- **Httpx** v1.3.9 - HTTP probe
- **Ffuf** v2.1.0 - Fuzzer
- **Sqlmap** (latest) - SQL injection

## Usage Examples

### Create a scan

```bash
curl -X POST http://localhost:3000/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

### Stream events

```bash
curl -N http://localhost:3000/events
```

### Get metrics

```bash
curl http://localhost:3000/metrics | jq
```

### List scans

```bash
curl http://localhost:3000/scans | jq
```

## Docker Compose Commands

### Start services

```bash
docker-compose up -d
```

### Stop services

```bash
docker-compose stop
```

### Restart services

```bash
docker-compose restart
```

### View logs

```bash
# All logs
docker-compose logs -f

# Last 100 lines
docker-compose logs --tail=100
```

### Update to latest version

```bash
git pull
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Remove everything (including data)

```bash
docker-compose down -v
```

## Troubleshooting

### Container won't start

Check logs:
```bash
docker-compose logs kheprimaat
```

Common issues:
- Port 3000 already in use
- Insufficient disk space
- Permissions on `/data` directory

### Tools not found

Verify tools are installed:
```bash
docker-compose exec kheprimaat which subfinder
docker-compose exec kheprimaat which nuclei
docker-compose exec kheprimaat which httpx
docker-compose exec kheprimaat which ffuf
docker-compose exec kheprimaat which sqlmap
```

### Database issues

Reset database:
```bash
docker-compose down
rm -rf data/kheprimaat.db*
docker-compose up -d
```

### High memory usage

Limit container resources in `docker-compose.yml`:

```yaml
services:
  kheprimaat:
    # ... other config
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 512M
```

## Security Considerations

### Running as non-root

The container runs as user `khepri` (UID 1000) for security.

### Network isolation

Use Docker networks to isolate KhepriMaat:

```yaml
networks:
  kheprimaat-network:
    driver: bridge
    internal: true  # No internet access
```

### Secrets management

**Never commit secrets to docker-compose.yml!**

Use environment files:

```bash
# .env file (gitignored)
SMTP_PASSWORD=mysecretpassword
SLACK_WEBHOOK_URL=https://hooks.slack.com/...

# docker-compose.yml
services:
  kheprimaat:
    env_file:
      - .env
```

Or use Docker secrets:

```yaml
secrets:
  smtp_password:
    external: true

services:
  kheprimaat:
    secrets:
      - smtp_password
```

## Health Checks

The container includes a health check that pings `/metrics` every 30 seconds.

Check health status:
```bash
docker-compose ps
```

Healthy output:
```
NAME          STATUS
kheprimaat    Up 5 minutes (healthy)
```

## Production Deployment

### Use a reverse proxy

Example with Nginx:

```nginx
server {
    listen 80;
    server_name kheprimaat.yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # SSE support
        proxy_buffering off;
        proxy_cache off;
    }
}
```

### Enable HTTPS

Use Let's Encrypt with Certbot or add TLS termination to your reverse proxy.

### Backup database

Automated backup script:

```bash
#!/bin/bash
BACKUP_DIR="/backups/kheprimaat"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR
docker-compose exec -T kheprimaat \
  sqlite3 /data/kheprimaat.db ".backup /data/backup_$DATE.db"
docker cp kheprimaat:/data/backup_$DATE.db $BACKUP_DIR/
```

### Monitor with Prometheus

Add Prometheus exporter for metrics scraping.

## Image Size

- **Base image**: debian:bookworm-slim (~150MB)
- **Rust binary**: ~50MB
- **Security tools**: ~100MB
- **Total**: ~300MB (optimized)

## Building Custom Images

### Custom base image

```dockerfile
# Use Alpine for smaller size
FROM alpine:3.19 as runtime
# ... rest of Dockerfile
```

### Add custom tools

```dockerfile
# Add your custom tool
RUN curl -sSL https://your-tool.com/download -o /usr/local/bin/yourtool && \
    chmod +x /usr/local/bin/yourtool
```

### Build with specific version

```bash
docker build --build-arg RUST_VERSION=1.75 -t kheprimaat:v1.0.0 .
```

## Kubernetes Deployment

Coming soon: Helm chart for Kubernetes deployment.

## Support

- **Issues**: https://github.com/ind4skylivey/kheprimaat/issues
- **Discussions**: https://github.com/ind4skylivey/kheprimaat/discussions

---

**Docker Image**: `kheprimaat:latest`  
**Maintainer**: ind4skylivey  
**License**: See LICENSE.txt
