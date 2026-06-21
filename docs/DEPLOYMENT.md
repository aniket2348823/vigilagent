# Deployment Guide - Vigilagent

Complete guide for deploying Vigilagent to production environments.

> Looking for the **Deep System Integration topology** (component map,
> environment variable matrix, persistent volumes for the
> coordinator)? See `deployment_topology.md`. The two docs complement
> each other: this file covers OS install + service management; the
> topology doc covers the runtime layout the coordinator needs.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Database Setup](#database-setup)
6. [Service Deployment](#service-deployment)
7. [Monitoring & Logging](#monitoring--logging)
8. [Backup & Recovery](#backup--recovery)
9. [Scaling](#scaling)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

**Minimum**:
- CPU: 4 cores
- RAM: 8GB
- Disk: 50GB SSD
- OS: Ubuntu 20.04+ / Debian 11+ / RHEL 8+

**Recommended**:
- CPU: 8+ cores
- RAM: 16GB+
- Disk: 100GB+ SSD
- OS: Ubuntu 22.04 LTS

### Software Dependencies

- Python 3.10+
- Node.js 18+
- PostgreSQL 14+
- Redis 6+
- Nginx 1.20+
- Docker 20+ (optional)
- Playwright browsers

---

## Environment Setup

### 1. Create Deployment User

```bash
# Create dedicated user
sudo useradd -m -s /bin/bash vigilagent
sudo usermod -aG sudo vigilagent

# Switch to user
sudo su - vigilagent
```

### 2. Install System Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y \
    python3.10 python3.10-venv python3-pip \
    postgresql postgresql-contrib \
    redis-server \
    nginx \
    git curl wget \
    build-essential libssl-dev libffi-dev

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs
```

### 3. Install Playwright Browsers

```bash
# Install Playwright
pip3 install playwright

# Install browsers
playwright install chromium
playwright install-deps
```

---

## Installation

### 1. Clone Repository

```bash
# Clone from repository
cd /opt
sudo git clone https://github.com/your-org/vigilagent.git
sudo chown -R vigilagent:vigilagent vigilagent
cd vigilagent
```

### 2. Create Virtual Environment

```bash
# Create venv
python3.10 -m venv venv

# Activate venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip setuptools wheel
```

### 3. Install Python Dependencies

```bash
# Install backend dependencies
pip install -r backend/requirements.txt

# Install test dependencies (optional)
pip install -r tests/requirements-test.txt
```

### 4. Install Frontend Dependencies

```bash
# Install Node packages
npm install

# Build frontend
npm run build
```

---

## Configuration

### 1. Environment Variables

Create `.env` file:

```bash
# Copy example
cp .env.example .env

# Edit configuration
nano .env
```

**Required Variables**:

```bash
# Application
APP_ENV=production
APP_DEBUG=false
APP_SECRET_KEY=<generate-secure-key>

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/vigilagent
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10

# Redis
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=<secure-password>

# Security
FORENSIC_ENCRYPTION_KEY=<generate-secure-key>
CSRF_SECRET_KEY=<generate-secure-key>
JWT_SECRET_KEY=<generate-secure-key>

# API
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4

# Browser
BROWSER_HEADLESS=true
BROWSER_MAX_CONTEXTS=10
BROWSER_MEMORY_THRESHOLD_MB=500

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/vigilagent/app.log

# Monitoring
SENTRY_DSN=<your-sentry-dsn>
PROMETHEUS_PORT=9090
```

### 2. Generate Secure Keys

```bash
# Generate secret keys
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Generate encryption key
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 3. Configure Nginx

Create `/etc/nginx/sites-available/vigilagent`:

```nginx
upstream vigilagent_backend {
    server 127.0.0.1:8000;
    keepalive 64;
}

server {
    listen 80;
    server_name your-domain.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Static Files
    location /static/ {
        alias /opt/vigilagent/dist/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # API Proxy
    location /api/ {
        proxy_pass http://vigilagent_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Rate Limiting
        limit_req zone=api burst=20 nodelay;
    }
    
    # WebSocket
    location /ws/ {
        proxy_pass http://vigilagent_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }
    
    # Frontend
    location / {
        root /opt/vigilagent/dist;
        try_files $uri $uri/ /index.html;
    }
}

# Rate Limiting Zone
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```

Enable site:

```bash
sudo ln -s /etc/nginx/sites-available/vigilagent /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## Database Setup

### 1. Create Database

```bash
# Connect to PostgreSQL
sudo -u postgres psql

# Create database and user
CREATE DATABASE vigilagent;
CREATE USER vigilagent_user WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE vigilagent TO vigilagent_user;
\q
```

### 2. Run Migrations

```bash
# Activate venv
source venv/bin/activate

# Run database migrations
python backend/db_migrate.py
```

### 3. Create Initial Data

```bash
# Create admin user
python backend/scripts/create_admin.py

# Load initial configuration
python backend/scripts/load_config.py
```

---

## Service Deployment

### 1. Create Systemd Service

Create `/etc/systemd/system/vigilagent.service`:

```ini
[Unit]
Description=Vigilagent Application
After=network.target postgresql.service redis.service

[Service]
Type=notify
User=vigilagent
Group=vigilagent
WorkingDirectory=/opt/vigilagent
Environment="PATH=/opt/vigilagent/venv/bin"
ExecStart=/opt/vigilagent/venv/bin/python backend/main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/vigilagent /opt/vigilagent/data

# Resource Limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

### 2. Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable vigilagent

# Start service
sudo systemctl start vigilagent

# Check status
sudo systemctl status vigilagent
```

### 3. Configure Log Rotation

Create `/etc/logrotate.d/vigilagent`:

```
/var/log/vigilagent/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 vigilagent vigilagent
    sharedscripts
    postrotate
        systemctl reload vigilagent > /dev/null 2>&1 || true
    endscript
}
```

---

## Monitoring & Logging

### 1. Application Logging

```bash
# View logs
sudo journalctl -u vigilagent -f

# View application logs
tail -f /var/log/vigilagent/app.log

# View error logs
tail -f /var/log/vigilagent/error.log
```

### 2. Prometheus Metrics

Access metrics at: `http://localhost:9090/metrics`

**Key Metrics**:
- `vigilagent_requests_total` - Total API requests
- `vigilagent_request_duration_seconds` - Request latency
- `vigilagent_active_scans` - Active scans
- `vigilagent_browser_contexts` - Browser contexts
- `vigilagent_memory_usage_bytes` - Memory usage

### 3. Health Checks

```bash
# Application health
curl http://localhost:8000/api/health

# Database health
curl http://localhost:8000/api/health/db

# Redis health
curl http://localhost:8000/api/health/redis
```

---

## Backup & Recovery

### 1. Database Backup

```bash
# Create backup script
cat > /opt/vigilagent/scripts/backup_db.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/vigilagent"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Backup database
pg_dump -U vigilagent_user vigilagent | gzip > $BACKUP_DIR/db_$DATE.sql.gz

# Keep only last 7 days
find $BACKUP_DIR -name "db_*.sql.gz" -mtime +7 -delete
EOF

chmod +x /opt/vigilagent/scripts/backup_db.sh
```

### 2. Schedule Backups

```bash
# Add to crontab
crontab -e

# Add line (daily at 2 AM)
0 2 * * * /opt/vigilagent/scripts/backup_db.sh
```

### 3. Restore from Backup

```bash
# Stop application
sudo systemctl stop vigilagent

# Restore database
gunzip < /var/backups/vigilagent/db_20260526_020000.sql.gz | \
    psql -U vigilagent_user vigilagent

# Start application
sudo systemctl start vigilagent
```

---

## Scaling

### 1. Horizontal Scaling

**Load Balancer Configuration** (HAProxy):

```
frontend vigilagent_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/vigilagent.pem
    default_backend vigilagent_backend

backend vigilagent_backend
    balance roundrobin
    option httpchk GET /api/health
    server app1 10.0.1.10:8000 check
    server app2 10.0.1.11:8000 check
    server app3 10.0.1.12:8000 check
```

### 2. Database Scaling

**Read Replicas**:

```python
# Configure in backend/core/database.py
DATABASES = {
    'default': {
        'ENGINE': 'postgresql',
        'HOST': 'primary.db.local',
        'PORT': 5432,
    },
    'replica': {
        'ENGINE': 'postgresql',
        'HOST': 'replica.db.local',
        'PORT': 5432,
    }
}
```

### 3. Redis Clustering

```bash
# Configure Redis Sentinel
sentinel monitor vigilagent 10.0.1.20 6379 2
sentinel down-after-milliseconds vigilagent 5000
sentinel failover-timeout vigilagent 10000
```

---

## Troubleshooting

### Common Issues

#### 1. Application Won't Start

```bash
# Check logs
sudo journalctl -u vigilagent -n 100

# Check permissions
ls -la /opt/vigilagent

# Check environment
source venv/bin/activate
python -c "import backend; print('OK')"
```

#### 2. Database Connection Errors

```bash
# Test connection
psql -U vigilagent_user -h localhost vigilagent

# Check PostgreSQL status
sudo systemctl status postgresql

# Check connection limits
sudo -u postgres psql -c "SHOW max_connections;"
```

#### 3. High Memory Usage

```bash
# Check browser contexts
curl http://localhost:8000/api/debug/contexts

# Force cleanup
curl -X POST http://localhost:8000/api/debug/cleanup

# Restart service
sudo systemctl restart vigilagent
```

#### 4. Slow Performance

```bash
# Check database queries
sudo -u postgres psql vigilagent -c "SELECT * FROM pg_stat_activity;"

# Check Redis
redis-cli INFO stats

# Check system resources
htop
```

---

## Security Checklist

- [ ] Change all default passwords
- [ ] Generate secure secret keys
- [ ] Enable HTTPS with valid certificate
- [ ] Configure firewall (UFW/iptables)
- [ ] Enable rate limiting
- [ ] Set up fail2ban
- [ ] Configure security headers
- [ ] Enable audit logging
- [ ] Set up intrusion detection
- [ ] Regular security updates
- [ ] Backup encryption keys
- [ ] Implement access controls

---

## Post-Deployment

### 1. Verify Deployment

```bash
# Run health checks
./scripts/health_check.sh

# Run smoke tests
pytest tests/smoke/ -v

# Check all services
systemctl status vigilagent nginx postgresql redis
```

### 2. Monitor for 24 Hours

- Watch error logs
- Monitor resource usage
- Check performance metrics
- Verify backups running

### 3. Documentation

- Document any custom configurations
- Update runbooks
- Train operations team
- Create incident response plan

---

## Support

For deployment issues:
- Check logs: `/var/log/vigilagent/`
- Review documentation: `docs/`
- Contact support: support@vigilagent.com

---

**Last Updated**: May 26, 2026  
**Version**: 5.0  
**Status**: Production Ready
