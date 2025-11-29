cat > install_deps.sh << 'EOF'
#!/bin/bash

echo "--- Xeron Dependency Installer ---"
echo ""

# 1. Update and Upgrade Termux Packages
echo "1. Updating Termux system packages..."
pkg update -y
pkg upgrade -y

# 2. Install Python
echo "2. Installing Python..."
pkg install python -y

# Check if Python installation was successful
if [ $? -eq 0 ]; then
    echo "Python installed successfully."
else
    echo "ERROR: Failed to install Python. Please check your Termux connection."
    exit 1
fi

# 3. Install Required Python Libraries
echo "3. Installing required Python libraries (requests and beautifulsoup4)..."

# Ensure pip is up-to-date
pip install --upgrade pip

# Install the core scraping libraries
pip install requests beautifulsoup4

# Check the exit status of the pip command
if [ $? -eq 0 ]; then
    echo ""
    echo "✨ All dependencies installed successfully! You are ready to run ./xeron.py"
else
    echo "ERROR: Failed to install required Python libraries. Please check pip output."
    exit 1
fi
EOF

chmod +x install_deps.sh && ./install_deps.sh
