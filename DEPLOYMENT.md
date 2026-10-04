# 🚀 PhishGuard AI - Deployment Guide

This guide covers deploying PhishGuard AI to production environments.

---

## Production Deployment Options

### 1. Docker Deployment (Recommended)

Create `Dockerfile` in backend directory:
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN python data/generate_dataset.py
RUN python model/train_model.py

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
```

Create `docker-compose.yml`:
```yaml
version: '3.8'
services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      - HOST=0.0.0.0
      - PORT=8000

  frontend:
    build: ./frontend
    ports:
      - "5173:5173"
    depends_on:
      - backend
```

### 2. Cloud Platform Deployment

#### Heroku
```bash
# Backend
echo "web: uvicorn app:app --host=0.0.0.0 --port=\$PORT" > Procfile
git add .
git commit -m "Deploy to Heroku"
heroku create phishguard-api
git push heroku main
```

#### Railway
```bash
railway login
railway new
railway add
railway deploy
```

#### Render
- Connect GitHub repository
- Set build command: `pip install -r requirements.txt && python setup.py`
- Set start command: `uvicorn app:app --host 0.0.0.0 --port $PORT`

### 3. VPS/Server Deployment

#### Using systemd (Ubuntu/Debian)

1. **Setup application**:
```bash
# Clone project
git clone <repository>
cd phishguard-ai

# Backend setup
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python setup.py
```

2. **Create systemd service** (`/etc/systemd/system/phishguard.service`):
```ini
[Unit]
Description=PhishGuard AI Backend
After=network.target

[Service]
Type=exec
User=www-data
WorkingDirectory=/opt/phishguard-ai/backend
Environment=PATH=/opt/phishguard-ai/backend/venv/bin
ExecStart=/opt/phishguard-ai/backend/venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

3. **Enable and start**:
```bash
sudo systemctl enable phishguard
sudo systemctl start phishguard
sudo systemctl status phishguard
```

---

## Frontend Deployment

### 1. Build for Production
```bash
cd frontend
npm run build
```

### 2. Serve Static Files

#### Nginx Configuration
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    
    # Frontend
    location / {
        root /opt/phishguard-ai/frontend/dist;
        try_files $uri $uri/ /index.html;
        
        # Security headers
        add_header X-Content-Type-Options nosniff;
        add_header X-Frame-Options DENY;
        add_header X-XSS-Protection "1; mode=block";
    }
    
    # Backend API
    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Apache Configuration
```apache
<VirtualHost *:80>
    ServerName yourdomain.com
    DocumentRoot /opt/phishguard-ai/frontend/dist
    
    # Frontend
    <Directory "/opt/phishguard-ai/frontend/dist">
        AllowOverride All
        Require all granted
        FallbackResource /index.html
    </Directory>
    
    # Backend API
    ProxyPass /api/ http://localhost:8000/api/
    ProxyPassReverse /api/ http://localhost:8000/api/
</VirtualHost>
```

---

## Configuration for Production

### 1. Backend Configuration

Update `backend/config.py`:
```python
import os

# Production settings
HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", 8000))

# CORS - Update for production domains
ALLOWED_ORIGINS = [
    "https://yourdomain.com",
    "https://www.yourdomain.com",
    # Remove localhost origins in production
]

# Security
RELOAD = False  # Disable in production
```

### 2. Frontend Configuration

Update `frontend/src/api/api.js`:
```javascript
// Production API base URL
const BASE_URL = process.env.NODE_ENV === 'production'
  ? 'https://yourdomain.com/api'
  : 'http://localhost:8000';
```

Or use environment variables in Vite:
```bash
# .env.production
VITE_API_BASE_URL=https://yourdomain.com/api
```

```javascript
// In api.js
const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
```

---

## Security Considerations

### 1. HTTPS/SSL
```bash
# Using Certbot for Let's Encrypt
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

### 2. Firewall Configuration
```bash
# UFW (Ubuntu)
sudo ufw allow 22    # SSH
sudo ufw allow 80    # HTTP
sudo ufw allow 443   # HTTPS
sudo ufw enable
```

### 3. Environment Variables
```bash
# Backend .env
export ALLOWED_ORIGINS="https://yourdomain.com,https://www.yourdomain.com"
export RELOAD=false
export PORT=8000
```

### 4. Rate Limiting
Add to FastAPI app:
```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/api/predict")
@limiter.limit("10/minute")
async def predict_url(request: Request, ...):
    # ... existing code
```

---

## Monitoring and Logging

### 1. Application Logging
```python
# In app.py
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phishguard.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
```

### 2. System Monitoring
```bash
# Monitor service
sudo journalctl -u phishguard -f

# Check resource usage
htop
```

### 3. Error Tracking
Consider integrating:
- **Sentry** for error tracking
- **Prometheus + Grafana** for metrics
- **ELK Stack** for log analysis

---

## Backup and Maintenance

### 1. Model Backup
```bash
# Backup trained models
tar -czf models-backup-$(date +%Y%m%d).tar.gz backend/model/
```

### 2. Automated Retraining
```bash
# Crontab entry for weekly retraining
0 2 * * 0 cd /opt/phishguard-ai/backend && /opt/phishguard-ai/backend/venv/bin/python model/train_model.py
```

### 3. Health Monitoring
```bash
#!/bin/bash
# health-check.sh
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/health)
if [ $response != "200" ]; then
    echo "API is down! Status: $response"
    sudo systemctl restart phishguard
fi
```

---

## Performance Optimization

### 1. Backend Optimization
```python
# Use Gunicorn for production
pip install gunicorn

# Start with multiple workers
gunicorn app:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### 2. Caching
```python
# Add Redis caching
from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend

@app.on_event("startup")
async def startup():
    redis = aioredis.from_url("redis://localhost")
    FastAPICache.init(RedisBackend(redis), prefix="phishguard")
```

### 3. Database (Optional)
For persistent history and analytics:
```python
# Add PostgreSQL support
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "postgresql://user:password@localhost/phishguard"
```

---

## Scaling Considerations

### 1. Load Balancing
```nginx
upstream phishguard_backend {
    server 127.0.0.1:8001;
    server 127.0.0.1:8002;
    server 127.0.0.1:8003;
}

location /api/ {
    proxy_pass http://phishguard_backend;
}
```

### 2. Container Orchestration
```yaml
# kubernetes-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: phishguard-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: phishguard-backend
  template:
    metadata:
      labels:
        app: phishguard-backend
    spec:
      containers:
      - name: backend
        image: phishguard/backend:latest
        ports:
        - containerPort: 8000
```

---

## Troubleshooting

### Common Issues

1. **Model loading fails**
   - Ensure model files exist in production
   - Check file permissions
   - Verify Python version compatibility

2. **CORS errors**
   - Update ALLOWED_ORIGINS in production config
   - Check frontend API base URL

3. **Memory issues**
   - Monitor RAM usage during ML inference
   - Consider model optimization for large-scale deployment

4. **SSL certificate issues**
   - Renew certificates automatically with Certbot
   - Check certificate expiration dates

### Logs to Monitor
- Application logs: `/var/log/phishguard.log`
- Nginx logs: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`
- System logs: `journalctl -u phishguard`

---

This deployment guide provides a solid foundation for production deployment. Adjust configurations based on your specific infrastructure and requirements.