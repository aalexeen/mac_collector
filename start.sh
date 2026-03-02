#!/bin/bash
# MAC Collector — interactive setup and launch script
#
# Usage:
#   ./start.sh              — configure (if needed) and start
#   ./start.sh --stop       — stop containers (data preserved)
#   ./start.sh --stop-reset — stop containers and delete database

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
COMPOSE="docker compose -f $SCRIPT_DIR/docker/docker-compose.yml --env-file $ENV_FILE"

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------

bold()  { printf '\033[1m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
yellow(){ printf '\033[33m%s\033[0m' "$*"; }
red()   { printf '\033[31m%s\033[0m' "$*"; }

# -------------------------------------------------------
# --stop / --stop-reset
# -------------------------------------------------------

if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo
    echo "$(bold "Usage:") ./start.sh [OPTION]"
    echo
    echo "  (no option)      Configure (if needed) and start MAC Collector"
    echo "  $(bold "--stop")           Stop containers, preserve database"
    echo "  $(bold "--stop-reset")     Stop containers and delete database"
    echo "  $(bold "--help")           Show this help"
    echo
    exit 0
fi

if [ "$1" = "--stop" ] || [ "$1" = "--stop-reset" ]; then
    if [ ! -f "$ENV_FILE" ]; then
        echo "$(red "Error:") .env not found — nothing to stop."
        exit 1
    fi
    if [ "$1" = "--stop-reset" ]; then
        echo "Stopping containers and $(red "deleting database")..."
        $COMPOSE down -v
    else
        echo "Stopping containers (data preserved)..."
        $COMPOSE down
    fi
    echo "$(green "Done.")"
    exit 0
fi

prompt() {
    # prompt <var_name> <display_name> <default>
    local var="$1" label="$2" default="$3"
    local value=""
    if [ -n "$default" ]; then
        read -rp "  $(bold "$label") [$(yellow "$default")]: " value
        value="${value:-$default}"
    else
        read -rp "  $(bold "$label"): " value
    fi
    eval "$var=\"$value\""
}

prompt_int() {
    # prompt_int <var_name> <display_name> <default>
    local var="$1" label="$2" default="$3"
    local value=""
    while true; do
        read -rp "  $(bold "$label") [$(yellow "$default")]: " value
        value="${value:-$default}"
        if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -gt 0 ]; then
            break
        fi
        echo "  $(red "Must be a positive integer.")"
    done
    eval "$var=\"$value\""
}

confirm_secret() {
    # confirm_secret <var_name> <display_name>
    local var="$1" label="$2"
    local value="" confirm=""
    while true; do
        read -rsp "  $(bold "$label"): " value; echo
        if [ -z "$value" ]; then
            echo "  $(red "Cannot be empty.")"
            continue
        fi
        read -rsp "  $(bold "Confirm $label"): " confirm; echo
        if [ "$value" = "$confirm" ]; then
            break
        fi
        echo "  $(red "Values do not match, try again.")"
    done
    eval "$var=\"$value\""
}

rand_hex() {
    # rand_hex <bytes> — generate random hex string, openssl or /dev/urandom fallback
    local bytes="$1"
    if command -v openssl &>/dev/null; then
        openssl rand -hex "$bytes" 2>/dev/null
    else
        xxd -l "$bytes" -p /dev/urandom 2>/dev/null || \
        od -vAn -N"$bytes" -tx1 /dev/urandom 2>/dev/null | tr -d ' \n'
    fi
}

# -------------------------------------------------------
# Dependency check
# -------------------------------------------------------

echo
echo "$(bold "MAC Collector — Setup")"
echo "─────────────────────────────────────────"
echo
echo "$(bold "Checking dependencies...")"

IS_UBUNTU=false
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" == "ubuntu" || "${ID_LIKE:-}" == *"ubuntu"* ]]; then
        IS_UBUNTU=true
    fi
fi

MISSING=()

# docker binary
if command -v docker &>/dev/null; then
    DOCKER_VER=$(docker --version 2>/dev/null | grep -oP '[\d.]+' | head -1)
    echo "  $(green "✓") docker ${DOCKER_VER}"
else
    echo "  $(red "✗") docker — not found"
    MISSING+=("docker.io")
fi

# docker compose plugin
if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
    COMPOSE_VER=$(docker compose version 2>/dev/null | grep -oP '[\d.]+' | head -1)
    echo "  $(green "✓") docker compose ${COMPOSE_VER}"
else
    echo "  $(red "✗") docker compose — not found"
    MISSING+=("docker-compose-v2")
fi

# openssl — not critical, we have a fallback
if command -v openssl &>/dev/null; then
    OPENSSL_VER=$(openssl version 2>/dev/null | awk '{print $2}')
    echo "  $(green "✓") openssl ${OPENSSL_VER}"
else
    echo "  $(yellow "!") openssl — not found (will use /dev/urandom fallback)"
fi

# -------------------------------------------------------
# Install missing dependencies
# -------------------------------------------------------

if [ ${#MISSING[@]} -gt 0 ]; then
    echo
    echo "  Missing: $(red "${MISSING[*]}")"
    echo

    if [ "$IS_UBUNTU" = true ]; then
        read -rp "  Install missing dependencies via apt? [Y/n]: " answer
        if [[ ! "$answer" =~ ^[Nn]$ ]]; then
            echo
            if ! sudo apt-get update -qq; then
                echo "  $(red "Error:") apt-get update failed."
                echo "  Please install manually: sudo apt install ${MISSING[*]}"
                echo "  Then re-run this script."
                exit 1
            fi
            if ! sudo apt-get install -y "${MISSING[@]}"; then
                echo "  $(red "Error:") Installation failed."
                echo "  Please install manually: sudo apt install ${MISSING[*]}"
                echo "  Then re-run this script."
                exit 1
            fi
            echo
            # Re-check after install
            STILL_MISSING=()
            for pkg in "${MISSING[@]}"; do
                case "$pkg" in
                    docker.io)
                        command -v docker &>/dev/null || STILL_MISSING+=("$pkg") ;;
                    docker-compose-v2)
                        docker compose version &>/dev/null 2>&1 || STILL_MISSING+=("$pkg") ;;
                    openssl)
                        command -v openssl &>/dev/null || STILL_MISSING+=("$pkg") ;;
                esac
            done
            if [ ${#STILL_MISSING[@]} -gt 0 ]; then
                echo "  $(red "Error:") Still missing after install: ${STILL_MISSING[*]}"
                echo "  Please check your system and re-run this script."
                exit 1
            fi
            echo "  $(green "Dependencies installed successfully.")"
        else
            echo "  $(yellow "Skipped.") Please install manually and re-run:"
            echo "  sudo apt install ${MISSING[*]}"
            exit 1
        fi
    else
        echo "  $(yellow "Note:") Automatic installation is only supported on Ubuntu."
        echo "  Please install the missing packages manually and re-run this script."
        echo
        # Not fatal — inform and continue only if docker is present
        if ! command -v docker &>/dev/null; then
            exit 1
        fi
    fi
else
    echo
    echo "  $(green "All dependencies satisfied.")"
fi

# -------------------------------------------------------
# Check Docker daemon access
# -------------------------------------------------------

if ! docker info &>/dev/null 2>&1; then
    echo
    echo "$(red "Error:") Cannot connect to Docker daemon."
    echo
    echo "  Most likely your user is not in the 'docker' group."
    echo "  Fix with:"
    echo "    sudo usermod -aG docker \$USER"
    echo "    newgrp docker"
    echo
    echo "  Then re-run this script."
    exit 1
fi

# -------------------------------------------------------
# If .env already exists — ask whether to reconfigure
# -------------------------------------------------------

if [ -f "$ENV_FILE" ]; then
    echo
    echo "$(yellow "Note:") .env already exists."
    read -rp "  Reconfigure? [y/N]: " answer
    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
        echo
        echo "Launching with existing configuration..."
        if ! $COMPOSE up --build -d; then
            echo
            echo "$(red "Error:") Failed to start containers."
            echo "  Check the output above for details."
            echo "  You can also run: ./start.sh --stop and then ./start.sh"
            exit 1
        fi
        echo
        echo "  To stop:                $(bold "./start.sh --stop")"
        echo "  To stop and reset DB:   $(bold "./start.sh --stop-reset")"
        echo
        echo "$(green "Done!") Open http://localhost:8000"
        exit 0
    fi
fi

# -------------------------------------------------------
# Interactive configuration
# -------------------------------------------------------

echo
echo "$(bold "Step 1 of 3 — SNMP")"
prompt SNMP_COMMUNITY "Community string" "public"

echo
echo "$(bold "Step 2 of 3 — Admin account")"
prompt         ADMIN_EMAIL    "Admin email"    "admin@example.com"
confirm_secret ADMIN_PASSWORD "Admin password"

echo
echo "$(bold "Step 3 of 3 — Display settings")"
prompt     DISPLAY_TZ       "Timezone (IANA)" "America/New_York"
prompt_int COLLECT_INTERVAL "Poll interval, seconds (e.g. 300 = 5 min, 60 = 1 min)" "300"

# Generate secrets automatically
SESSION_SECRET=$(rand_hex 32)
DB_PASSWORD=$(rand_hex 16)

if [ -z "$SESSION_SECRET" ] || [ -z "$DB_PASSWORD" ]; then
    echo
    echo "$(red "Error:") Failed to generate random secrets."
    echo "  Make sure openssl or /dev/urandom is available."
    exit 1
fi

# -------------------------------------------------------
# Write .env
# -------------------------------------------------------

if ! cat > "$ENV_FILE" <<EOF
# MAC Collector — generated by start.sh

SNMP_COMMUNITY=${SNMP_COMMUNITY}

COLLECT_INTERVAL=${COLLECT_INTERVAL}

DISPLAY_TZ=${DISPLAY_TZ}

ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASSWORD}

SESSION_SECRET=${SESSION_SECRET}

DB_PASSWORD=${DB_PASSWORD}
EOF
then
    echo
    echo "$(red "Error:") Failed to write .env to ${ENV_FILE}"
    echo "  Check write permissions for: $SCRIPT_DIR"
    exit 1
fi

echo
echo "$(green "Configuration saved to .env")"

# -------------------------------------------------------
# Launch
# -------------------------------------------------------

echo
echo "$(bold "Starting MAC Collector...")"
if ! $COMPOSE up --build -d; then
    echo
    echo "$(red "Error:") Failed to start containers."
    echo "  Check the output above for details."
    echo "  You can also run: ./start.sh --stop and then ./start.sh"
    exit 1
fi

echo
echo "  To stop:                $(bold "./start.sh --stop")"
echo "  To stop and reset DB:   $(bold "./start.sh --stop-reset")"
echo
echo "$(green "Done!") Open http://localhost:8000"
echo "  Login: $(bold "$ADMIN_EMAIL")"
