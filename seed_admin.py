"""CLI: create the first admin user.

Usage:
    python seed_admin.py --email admin@corp.local [--password ...]
    python seed_admin.py --email admin@corp.local  # prompts for password
"""

import argparse
import asyncio
import getpass
import sys

from auth import hash_password
from db import Database


async def _create(email: str, password: str) -> None:
    db = Database()
    await db.connect()
    try:
        existing = await db.get_user_by_email(email)
        if existing:
            print(f"[error] User '{email}' already exists.", file=sys.stderr)
            sys.exit(1)
        await db.create_user(email, hash_password(password), "admin")
        print(f"[ok] Admin user '{email}' created.")
    finally:
        await db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Create first admin user")
    parser.add_argument("--email", required=True, help="Admin email address")
    parser.add_argument("--password", default=None, help="Password (min 12 chars)")
    args = parser.parse_args()

    password = args.password
    if password is None:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("[error] Passwords do not match.", file=sys.stderr)
            sys.exit(1)

    if len(password) < 12:
        print("[error] Password must be at least 12 characters.", file=sys.stderr)
        sys.exit(1)

    asyncio.run(_create(args.email, password))


if __name__ == "__main__":
    main()
