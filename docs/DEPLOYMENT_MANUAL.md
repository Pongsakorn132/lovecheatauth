# KawaiiAuth — Production Deployment & Hardening Manual

This document covers deploying KawaiiAuth on an Ubuntu 22.04 / 24.04 VPS with Nginx, SSL certificates, Rate Limiting, and PM2/Docker.

---

## Option 1: Native Node.js + PM2 (Recommended & Fastest)

### Step 1: Install Node.js (v22+)
```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### Step 2: Transfer and Start Server
```bash
cd /opt/kawaiiauth/server
npm install pm2 -g
pm2 start src/server.js --name "kawaiiauth" --env PORT=8080
pm2 save
pm2 startup
```

---

## Option 2: Docker & Docker Compose

Save the following in `docker-compose.yml`:

```yaml
version: '3.8'

services:
  kawaiiauth:
    build: ./server
    restart: always
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      - PORT=8080
      - ADMIN_KEY=your_very_secure_master_key_1337
    volumes:
      - ./server/data:/app/data
```

With Dockerfile in `./server/Dockerfile`:
```dockerfile
FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
COPY src/ ./src/
EXPOSE 8080
CMD ["node", "src/server.js"]
```

Run with:
```bash
docker compose up -d
```

---

## 3. Nginx Reverse Proxy & SSL Configuration

Install Nginx & Certbot:
```bash
sudo apt-get install -y nginx certbot python3-certbot-nginx
```

Create `/etc/nginx/sites-available/kawaiiauth.conf`:
```nginx
# Rate limiting zone (50 req/sec per IP)
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=50r/s;

server {
    server_name auth.yourdomain.com;

    location / {
        limit_req zone=api_limit burst=20 nodelay;

        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    # Hide server signatures
    server_tokens off;
}
```

Enable site and acquire SSL:
```bash
sudo ln -s /etc/nginx/sites-available/kawaiiauth.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d auth.yourdomain.com
```

---

## 4. Cloudflare Proxy Configuration

When routing through Cloudflare:
1. Set SSL/TLS Encryption mode to **Full (Strict)**.
2. In **Security** -> **WAF**, enable Bot Fight Mode.
3. In **Page Rules / Cache Rules**, bypass cache for `/api/*` so requests hit the backend origin directly.
