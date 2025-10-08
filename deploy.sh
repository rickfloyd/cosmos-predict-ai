#!/bin/bash

# Cosmos Predict AI - Quick Deploy Script for DigitalOcean
# Therapeutic AI Companions for Veterans & Disabled Individuals

echo "🎖️  Deploying Cosmos Predict AI - Therapeutic Platform for Veterans"
echo "Built by disabled veteran with 8 years PTSD research"
echo ""

# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PM2 for process management
sudo npm install -g pm2

# Create app directory
sudo mkdir -p /var/www/cosmos-predict-ai
cd /var/www/cosmos-predict-ai

# Clone or copy your code here
echo "📁 Ready for your application files..."

# Install dependencies (run this after copying files)
# npm install

# Start the application
# pm2 start ecosystem.config.js
# pm2 startup
# pm2 save

echo "✅ Server setup complete!"
echo "🎯 Next: Copy your application files and run 'npm install'"
echo "🚀 Then: 'pm2 start ecosystem.config.js' to launch"