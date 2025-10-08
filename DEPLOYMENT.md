# DigitalOcean Deployment Configuration

## Server Setup

### 1. Create DigitalOcean Droplet
```bash
# Recommended: Ubuntu 22.04 LTS
# Size: 2GB RAM, 1 vCPU minimum
# Choose datacenter region closest to your users
```

### 2. Install Node.js and Dependencies
```bash
# SSH into your droplet
ssh root@your_droplet_ip

# Update system
apt update && apt upgrade -y

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
apt-get install -y nodejs

# Install PM2 for process management
npm install -g pm2

# Install Nginx for reverse proxy
apt install nginx -y
```

### 3. Deploy the Application
```bash
# Clone your repository
git clone https://github.com/YOUR_USERNAME/cosmos-predict-ai.git
cd cosmos-predict-ai

# Install dependencies
npm install

# Build the application
npm run build

# Start with PM2
pm2 start ecosystem.config.js
pm2 startup
pm2 save
```

### 4. Configure Nginx
```nginx
# /etc/nginx/sites-available/cosmos-predict-ai
server {
    listen 80;
    server_name your_domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### 5. SSL Certificate (Optional but Recommended)
```bash
# Install Certbot
apt install certbot python3-certbot-nginx -y

# Get SSL certificate
certbot --nginx -d your_domain.com

# Auto-renewal
crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## Environment Variables

Create `/var/www/cosmos-predict-ai/.env`:
```env
NODE_ENV=production
PORT=3000
OPENAI_API_KEY=your_openai_api_key
GOOGLE_CLOUD_API_KEY=your_google_veo_key
VADOO_API_KEY=your_vadoo_key
PREDIS_API_KEY=your_predis_key
```

## Monitoring and Maintenance

### PM2 Commands
```bash
# View logs
pm2 logs cosmos-predict-ai

# Restart application
pm2 restart cosmos-predict-ai

# Monitor
pm2 monit

# Update application
git pull origin main
npm install
npm run build
pm2 restart cosmos-predict-ai
```

### System Monitoring
```bash
# Check system resources
htop

# Check disk space
df -h

# Check memory usage
free -h

# Check active connections
netstat -tulpn
```

## Scaling Considerations

### Load Balancing (Multiple Droplets)
```bash
# Use DigitalOcean Load Balancer
# Configure health checks on port 3000
# Enable sticky sessions for chat continuity
```

### Database Integration (Future)
```bash
# Consider DigitalOcean Managed PostgreSQL
# For user profiles and chat history
# Redis for session management
```

### CDN Integration
```bash
# Use DigitalOcean Spaces + CDN
# For video content delivery
# Reduce server load
```

## Security Best Practices

1. **Firewall Configuration**
```bash
ufw enable
ufw allow ssh
ufw allow 'Nginx Full'
```

2. **API Rate Limiting**
```javascript
// Add to your app
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);
```

3. **Regular Updates**
```bash
# Weekly system updates
apt update && apt upgrade -y

# Monthly security audits
npm audit
```

## Backup Strategy

```bash
# Daily database backups (if using database)
0 2 * * * pg_dump cosmos_predict_ai > /backups/db_$(date +\%Y\%m\%d).sql

# Weekly code backups
0 3 * * 0 tar -czf /backups/app_$(date +\%Y\%m\%d).tar.gz /var/www/cosmos-predict-ai

# DigitalOcean Snapshots (Recommended)
# Enable automatic weekly snapshots in DO panel
```

## Cost Optimization

### Recommended DigitalOcean Setup
- **Development**: 1GB RAM Droplet ($6/month)
- **Production**: 2GB RAM Droplet ($12/month) 
- **High Traffic**: 4GB RAM Droplet ($24/month)
- **Load Balancer**: $12/month (for scaling)
- **Managed Database**: $25/month (when needed)

### Total Monthly Cost Estimate
- **Starter**: $6-12/month
- **Growth**: $24-50/month
- **Scale**: $100+/month

Ready for deployment! 🚀