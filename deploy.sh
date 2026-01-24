#!/bin/bash

echo "🚀 Starting CRM Deployment..."

cd /www/wwwroot/CRM-Server || exit 1

echo "🧹 Cleaning local changes..."
git reset --hard
git clean -fd -e Uploads

echo "⬇️ Pulling latest code..."
git pull origin main

echo "📦 Installing dependencies..."
rm -rf node_modules
npm install --production

echo "🔁 Restarting PM2 service..."
pm2 restart crm

echo "✅ CRM Deployment completed successfully!"
