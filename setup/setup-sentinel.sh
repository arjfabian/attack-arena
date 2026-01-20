#!/bin/bash
# ATT&CK-ARENA: Sentinel Deployment Orchestrator
# ---------------------------------------------------------
RAW_BASE="https://raw.githubusercontent.com/arjfabian/attack-arena/refs/heads/main/setup/configs"

echo -e "\e[36mSENTINEL ORCHESTRATOR\e[0m"

# 1. PREREQUISITE CHECK: Docker & Compose
echo -e "\e[90m[*] Checking prerequisites...\e[0m"

if ! command -v docker &> /dev/null; then
    echo -e "\e[31m[!] Error: Docker is not installed.\e[0m"
    echo -e "\e[33mTip: Install it with 'sudo apt update && sudo apt install docker.io -y'\e[0m"
    exit 1
fi

# Check for Docker Compose (plugin or standalone)
if ! docker compose version &> /dev/null && ! command -v docker-compose &> /dev/null; then
    echo -e "\e[31m[!] Error: Docker Compose is not found.\e[0m"
    echo -e "\e[33mTip: Install it with 'sudo apt install docker-compose-v2 -y'\e[0m"
    exit 1
fi

# Permission hint for non-root users
if [[ $(groups) != *"docker"* ]] && [ "$EUID" -ne 0 ]; then
    echo -e "\e[33m[!] Warning: You may need 'sudo' to run Docker commands if not in the docker group.\e[0m"
fi

echo -e "\e[32m[+] Docker environment detected.\e[0m"

# 2. Environment Preparation
mkdir -p ./logstash/pipeline

# 3. Fetch Immutable Assets from GitHub
echo -e "\e[90m[*] Fetching latest configuration assets from GitHub...\e[0m"
curl -sSL "$RAW_BASE/docker-compose.yml" -o docker-compose.yml
curl -sSL "$RAW_BASE/logstash.conf" -o ./logstash/pipeline/logstash.conf

# 4. Asset Validation
if [ ! -s "docker-compose.yml" ]; then
    echo -e "\e[31m[!] Error: Failed to download docker-compose.yml (File is empty or missing).\e[0m"
    exit 1
fi

# 5. Execution
echo -e "\e[32m[+] Assets synchronized.\e[0m"
read -p "Deploy Sentinel stack now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "\e[90m[*] Launching containers...\e[0m"
    # Try the modern 'docker compose' first, fallback to 'docker-compose'
    docker compose up -d || docker-compose up -d
    echo -e "\e[36mSENTINEL IS LIVE. Monitor progress at http://localhost:5601\e[0m"
else
    echo -e "To start manually, run: \e[33mdocker compose up -d\e[0m"
fi