#!/usr/bin/env bash
# install.sh — Production installer for MAC Collector
#
# Usage:
#   sudo ./install.sh           # fresh install or upgrade
#   sudo ./install.sh --dry-run # show what would be done
#
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
APP_NAME="mac-collector"
APP_USER="mac_collector"
APP_GROUP="mac_collector"
APP_DIR="/opt/mac-collector"
CONFIG_DIR="/etc/mac-collector"
VENV="$APP_DIR/venv"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Application source files to install
APP_FILES=(
    web.py
    db.py
    auth.py
    arp_collector.py
    fdb_collector.py
    seed_admin.py
)

# ── CLI flags ─────────────────────────────────────────────────────────────────
DRY_RUN=false
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}  ✔${NC}  $*"; }
warn() { echo -e "${YELLOW}  ⚠${NC}  $*"; }
die()  { echo -e "${RED}  ✘${NC}  $*" >&2; exit 1; }
step() { echo -e "\n${BOLD}── $* ──${NC}"; }

run() {
    if $DRY_RUN; then
        echo -e "    ${YELLOW}[dry-run]${NC} $*"
    else
        "$@"
    fi
}

# Read a value from a key=value env file (handles = signs in values)
env_get() {
    local key="$1" file="$2"
    grep -E "^${key}=" "$file" 2>/dev/null | head -1 | cut -d= -f2-
}

# ── Preflight checks ──────────────────────────────────────────────────────────
step "Preflight"

[[ $EUID -eq 0 ]] || die "Run as root:  sudo $0"

if $DRY_RUN; then
    warn "DRY-RUN mode — no changes will be made"
fi

# Find Python 3.12 / 3.11 / 3.x
PYTHON=""
for candidate in python3.12 python3.11 python3; do
    if command -v "$candidate" &>/dev/null; then
        PYTHON=$(command -v "$candidate")
        break
    fi
done
[[ -n "$PYTHON" ]] || die "python3 not found — install: apt install python3"
log "Python: $("$PYTHON" --version)"

# snmpwalk is required by the collectors at runtime
if command -v snmpwalk &>/dev/null; then
    log "snmpwalk: found"
else
    warn "snmpwalk not found — install: apt install snmp"
fi

# psql is needed for schema setup (optional: may be remote)
if command -v psql &>/dev/null; then
    log "psql: found"
else
    warn "psql not found — schema setup will be skipped (install: apt install postgresql-client)"
fi

# requirements.txt must exist next to install.sh
[[ -f "$SOURCE_DIR/requirements.txt" ]] \
    || die "requirements.txt not found in $SOURCE_DIR"
log "requirements.txt: found"

# ── System user ───────────────────────────────────────────────────────────────
step "System user"

if id "$APP_USER" &>/dev/null; then
    log "User '$APP_USER' already exists"
else
    run useradd \
        --system \
        --no-create-home \
        --home-dir /nonexistent \
        --shell /usr/sbin/nologin \
        --comment "MAC Collector service account" \
        "$APP_USER"
    log "Created system user '$APP_USER' (nologin)"
fi

# ── Directories ───────────────────────────────────────────────────────────────
step "Directories"

# /opt/mac-collector/         — application code + venv (root:root 755)
# /opt/mac-collector/templates — Jinja2 templates     (root:root 755)
# /etc/mac-collector/         — config (.env)          (root:mac_collector 750)
run install -d -m 755 -o root -g root         "$APP_DIR"
run install -d -m 755 -o root -g root         "$APP_DIR/templates"
run install -d -m 750 -o root -g "$APP_GROUP" "$CONFIG_DIR"
log "$APP_DIR"
log "$APP_DIR/templates"
log "$CONFIG_DIR  (group=$APP_GROUP, mode=750)"

# ── Application files ─────────────────────────────────────────────────────────
step "Application files → $APP_DIR"

for f in "${APP_FILES[@]}"; do
    src="$SOURCE_DIR/$f"
    if [[ -f "$src" ]]; then
        run install -m 644 -o root -g root "$src" "$APP_DIR/$f"
        log "$f"
    else
        warn "$f not found in source — skipping"
    fi
done

# Copy templates/ directory
if $DRY_RUN; then
    log "templates/ (dry-run)"
else
    cp -a "$SOURCE_DIR/templates/." "$APP_DIR/templates/"
    chown -R root:root "$APP_DIR/templates"
    find "$APP_DIR/templates" -type d -exec chmod 755 {} \;
    find "$APP_DIR/templates" -type f -exec chmod 644 {} \;
    log "templates/"
fi

# ── Python virtual environment ────────────────────────────────────────────────
step "Python virtual environment → $VENV"

if $DRY_RUN; then
    log "venv (dry-run)"
else
    if [[ ! -d "$VENV" ]]; then
        "$PYTHON" -m venv "$VENV"
        log "Created venv ($("$PYTHON" --version))"
    else
        log "venv already exists — reusing"
    fi

    "$VENV/bin/pip" install --quiet --upgrade pip
    "$VENV/bin/pip" install --quiet -r "$SOURCE_DIR/requirements.txt"
    chown -R root:root "$VENV"
    log "Dependencies installed from requirements.txt"
fi

# ── Configuration ─────────────────────────────────────────────────────────────
step "Configuration → $CONFIG_DIR"

ENV_TARGET="$CONFIG_DIR/.env"

if [[ -f "$ENV_TARGET" ]]; then
    log ".env already exists — not overwriting (edit manually if needed)"
elif [[ -f "$SOURCE_DIR/.env" ]]; then
    run install -m 640 -o root -g "$APP_GROUP" "$SOURCE_DIR/.env" "$ENV_TARGET"
    log "Installed .env from source (readable by $APP_GROUP only)"
else
    if ! $DRY_RUN; then
        cat > "$ENV_TARGET" <<'EOF'
# ── SNMP ──────────────────────────────────────────────────────────────────────
SNMP_COMMUNITY=public

# ── PostgreSQL ────────────────────────────────────────────────────────────────
DB_HOST=localhost
DB_PORT=5432
DB_NAME=mac_collector
DB_USER=mac_collector_user
DB_PASSWORD=CHANGE_ME

# ── Web session ───────────────────────────────────────────────────────────────
# Generate with: openssl rand -hex 32
SESSION_SECRET=CHANGE_ME
EOF
        chmod 640 "$ENV_TARGET"
        chown root:"$APP_GROUP" "$ENV_TARGET"
    fi
    warn "Created .env template — edit $ENV_TARGET before starting services!"
fi

# ── Database schema ───────────────────────────────────────────────────────────
step "Database schema"

if ! command -v psql &>/dev/null; then
    warn "psql not found — skipping schema setup"
    warn "Apply manually: psql -h <host> -U <user> -d <db> -f $SOURCE_DIR/schema.sql"
else
    # Determine which .env to read credentials from
    if [[ -f "$CONFIG_DIR/.env" ]]; then
        _ENV_FILE="$CONFIG_DIR/.env"
    elif [[ -f "$SOURCE_DIR/.env" ]]; then
        _ENV_FILE="$SOURCE_DIR/.env"
    else
        _ENV_FILE=""
    fi

    if [[ -z "$_ENV_FILE" ]]; then
        warn "No .env found — skipping schema setup"
        warn "Apply manually after configuring $CONFIG_DIR/.env"
    else
        _DB_HOST=$(env_get DB_HOST "$_ENV_FILE")
        _DB_PORT=$(env_get DB_PORT "$_ENV_FILE")
        _DB_NAME=$(env_get DB_NAME "$_ENV_FILE")
        _DB_USER=$(env_get DB_USER "$_ENV_FILE")
        _DB_PASS=$(env_get DB_PASSWORD "$_ENV_FILE")

        log "Checking database ${_DB_NAME}@${_DB_HOST}:${_DB_PORT} ..."

        if $DRY_RUN; then
            log "schema check + apply (dry-run)"
        else
            # Check if the 'switches' table already exists — proxy for "schema applied"
            _TABLE_EXISTS=$(PGPASSWORD="$_DB_PASS" psql \
                -h "$_DB_HOST" -p "$_DB_PORT" \
                -U "$_DB_USER" -d "$_DB_NAME" \
                -tAc "SELECT to_regclass('public.switches')" 2>/dev/null || true)

            if [[ "$_TABLE_EXISTS" == "switches" ]]; then
                warn "Database '$_DB_NAME' already contains the schema — skipping"
                warn "To re-apply manually: psql -h $_DB_HOST -U $_DB_USER -d $_DB_NAME -f $SOURCE_DIR/schema.sql"
            else
                log "Applying schema.sql ..."
                if PGPASSWORD="$_DB_PASS" psql \
                        -h "$_DB_HOST" -p "$_DB_PORT" \
                        -U "$_DB_USER" -d "$_DB_NAME" \
                        -f "$SOURCE_DIR/schema.sql" 2>&1; then
                    log "schema.sql applied successfully"
                else
                    warn "Failed to apply schema.sql — check DB credentials in $CONFIG_DIR/.env"
                    warn "Apply manually: psql -h $_DB_HOST -U $_DB_USER -d $_DB_NAME -f $SOURCE_DIR/schema.sql"
                fi
            fi
        fi
    fi
fi

# ── systemd unit files ────────────────────────────────────────────────────────
step "systemd units → /etc/systemd/system"

install_unit() {
    local name="$1"
    local content="$2"
    local dest="/etc/systemd/system/$name"
    if $DRY_RUN; then
        log "$name (dry-run)"
    else
        echo "$content" > "$dest"
        chmod 644 "$dest"
        log "$name"
    fi
}

install_unit "mac-collector-web.service" "[Unit]
Description=MAC Collector — Web Application
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_DIR
EnvironmentFile=$CONFIG_DIR/.env
ExecStart=$VENV/bin/uvicorn web:app --host 127.0.0.1 --port 8000 --workers 2
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict

[Install]
WantedBy=multi-user.target"

install_unit "mac-collector-arp.service" "[Unit]
Description=MAC Collector — ARP collection (one-shot)
After=network.target postgresql.service

[Service]
Type=oneshot
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_DIR
EnvironmentFile=$CONFIG_DIR/.env
ExecStart=$VENV/bin/python arp_collector.py
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict"

install_unit "mac-collector-arp.timer" "[Unit]
Description=Run ARP collector every 5 minutes
Requires=mac-collector-arp.service

[Timer]
OnBootSec=30
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target"

install_unit "mac-collector-fdb.service" "[Unit]
Description=MAC Collector — FDB collection (one-shot)
After=network.target postgresql.service

[Service]
Type=oneshot
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_DIR
EnvironmentFile=$CONFIG_DIR/.env
ExecStart=$VENV/bin/python fdb_collector.py
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict"

install_unit "mac-collector-fdb.timer" "[Unit]
Description=Run FDB collector every 5 minutes
Requires=mac-collector-fdb.service

[Timer]
OnBootSec=60
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target"

# ── Enable & start services ───────────────────────────────────────────────────
step "Enabling services"

if $DRY_RUN; then
    log "daemon-reload (dry-run)"
    log "mac-collector-web.service  enable + restart (dry-run)"
    log "mac-collector-arp.timer    enable + start   (dry-run)"
    log "mac-collector-fdb.timer    enable + start   (dry-run)"
else
    systemctl daemon-reload

    # Web: restart so updated code takes effect on upgrades too
    systemctl enable mac-collector-web.service
    systemctl restart mac-collector-web.service
    log "mac-collector-web.service  [enabled, started]"

    # Timers: enable --now is idempotent
    systemctl enable --now mac-collector-arp.timer
    log "mac-collector-arp.timer    [enabled]"

    systemctl enable --now mac-collector-fdb.timer
    log "mac-collector-fdb.timer    [enabled]"
fi

# ── Post-install summary ──────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  ${GREEN}MAC Collector installed successfully${NC}${BOLD}            ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Application:${NC}  $APP_DIR"
echo -e "  ${BOLD}Config:${NC}       $CONFIG_DIR/.env"
echo -e "  ${BOLD}Service user:${NC} $APP_USER (nologin)"
echo ""
echo -e "  ${BOLD}Useful commands:${NC}"
echo "    systemctl status mac-collector-web"
echo "    systemctl list-timers mac-collector-*"
echo "    journalctl -u mac-collector-web -f"
echo "    journalctl -u mac-collector-arp --since today"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo "    1. Review/edit config:  $CONFIG_DIR/.env"
echo "    2. Create first admin:  sudo -u $APP_USER \\"
echo "         $VENV/bin/python $APP_DIR/seed_admin.py"
echo "    3. Open:                http://localhost:8000"
echo ""
