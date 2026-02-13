#!/bin/bash

# Phishing Detection Platform - Setup Script for Fedora
# This script automates the setup process

set -e  # Exit on error

echo "=========================================="
echo "🔐 Phishing Detection Platform Setup"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get current directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo -e "${YELLOW}Step 1: Installing system dependencies...${NC}"
echo "You may need to enter your password for sudo commands"
echo ""

# Update system
echo "Updating Fedora packages..."
sudo dnf update -y > /dev/null 2>&1

# Install required packages
echo "Installing Python 3, SQLite, and build tools..."
sudo dnf install -y python3 python3-devel python3-pip sqlite sqlite-devel gcc gcc-c++ make nodejs npm > /dev/null 2>&1

echo -e "${GREEN}✓ System dependencies installed${NC}"
echo ""

# Backend Setup
echo -e "${YELLOW}Step 2: Setting up Backend...${NC}"
cd "$SCRIPT_DIR/backend"

echo "Creating Python virtual environment..."
python3 -m venv venv

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing Python dependencies..."
pip install --upgrade pip setuptools wheel > /dev/null 2>&1
pip install -r requirements.txt > /dev/null 2>&1

echo "Creating environment file..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${YELLOW}✓ .env file created. Update SECRET_KEY and JWT_SECRET_KEY for production!${NC}"
else
    echo -e "${GREEN}✓ .env file already exists${NC}"
fi

echo -e "${GREEN}✓ Backend setup complete${NC}"
echo ""

# Frontend Setup
echo -e "${YELLOW}Step 3: Setting up Frontend...${NC}"
cd "$SCRIPT_DIR/frontend"

echo "Creating environment file..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${GREEN}✓ .env file created${NC}"
else
    echo -e "${GREEN}✓ .env file already exists${NC}"
fi

echo "Installing npm dependencies..."
npm install > /dev/null 2>&1

echo -e "${GREEN}✓ Frontend setup complete${NC}"
echo ""

# Summary
echo "=========================================="
echo -e "${GREEN}✓ Setup Complete!${NC}"
echo "=========================================="
echo ""
echo -e "${YELLOW}To run the application:${NC}"
echo ""
echo "Terminal 1 - Backend (Flask API):"
echo "  cd $SCRIPT_DIR/backend"
echo "  source venv/bin/activate"
echo "  python3 run.py"
echo ""
echo "Terminal 2 - Frontend (React):"
echo "  cd $SCRIPT_DIR/frontend"
echo "  npm run dev"
echo ""
echo "Then open: http://localhost:5173"
echo ""
echo -e "${YELLOW}Default test account:${NC}"
echo "  Username: testuser"
echo "  Password: TestPass123!"
echo ""
echo "For more info, see: README.md"
echo "=========================================="
