#!/bin/sh
set -e

echo "[entrypoint] Waiting for PostgreSQL..."
until python - <<'EOF'
import asyncpg, asyncio, os, sys
async def check():
    try:
        conn = await asyncpg.connect(
            host=os.environ.get("DB_HOST", "db"),
            port=int(os.environ.get("DB_PORT", "5432")),
            database=os.environ.get("DB_NAME", "mac_collector"),
            user=os.environ.get("DB_USER", "mac_collector_user"),
            password=os.environ.get("DB_PASSWORD", ""),
        )
        await conn.close()
    except Exception:
        sys.exit(1)
asyncio.run(check())
EOF
do
    echo "[entrypoint] PostgreSQL not ready, retrying in 2s..."
    sleep 2
done
echo "[entrypoint] PostgreSQL is ready."

echo "[entrypoint] Applying schema..."
python - <<'EOF'
import asyncpg, asyncio, os
async def apply():
    conn = await asyncpg.connect(
        host=os.environ.get("DB_HOST", "db"),
        port=int(os.environ.get("DB_PORT", "5432")),
        database=os.environ.get("DB_NAME", "mac_collector"),
        user=os.environ.get("DB_USER", "mac_collector_user"),
        password=os.environ.get("DB_PASSWORD", ""),
    )
    with open("/app/schema.sql") as f:
        sql = f.read()
    await conn.execute(sql)
    await conn.close()
    print("[entrypoint] Schema applied.")
asyncio.run(apply())
EOF

echo "[entrypoint] Seeding admin user..."
python - <<'EOF'
import asyncpg, asyncio, os
from auth import hash_password

ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL",    "admin@demo.local")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")

async def seed():
    conn = await asyncpg.connect(
        host=os.environ.get("DB_HOST", "db"),
        port=int(os.environ.get("DB_PORT", "5432")),
        database=os.environ.get("DB_NAME", "mac_collector"),
        user=os.environ.get("DB_USER", "mac_collector_user"),
        password=os.environ.get("DB_PASSWORD", ""),
    )
    existing = await conn.fetchrow("SELECT id FROM users WHERE email = $1", ADMIN_EMAIL)
    if existing:
        print(f"[entrypoint] Admin '{ADMIN_EMAIL}' already exists, skipping.")
    else:
        import uuid_utils
        uid = str(uuid_utils.uuid7())
        pw_hash = hash_password(ADMIN_PASSWORD)
        await conn.execute(
            "INSERT INTO users (id, email, password_hash, role) VALUES ($1, $2, $3, 'admin')",
            uid, ADMIN_EMAIL, pw_hash,
        )
        print(f"[entrypoint] Admin '{ADMIN_EMAIL}' created.")
    await conn.close()

asyncio.run(seed())
EOF

echo "[entrypoint] Starting collector in background..."
python -u collector_loop.py &

echo "[entrypoint] Starting web server..."
exec uvicorn web:app --host 0.0.0.0 --port 8000
