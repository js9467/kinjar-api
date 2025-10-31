#!/usr/bin/env python3
"""
Script to create a global admin user directly in the database.
Use this if you can't set ROOT_EMAILS environment variable.
"""
import os
import sys
import uuid
from argon2 import PasswordHasher
import psycopg
from psycopg.rows import dict_row

def create_admin_user(email: str, password: str):
    DATABASE_URL = os.getenv("DATABASE_URL")
    if not DATABASE_URL:
        print("ERROR: DATABASE_URL environment variable not set")
        sys.exit(1)
    
    if len(password) < 8:
        print("ERROR: Password must be at least 8 characters")
        sys.exit(1)
    
    ph = PasswordHasher()
    password_hash = ph.hash(password)
    user_id = str(uuid.uuid4())
    
    try:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                # Check if user already exists
                cur.execute("SELECT id, global_role FROM users WHERE email = %s", (email,))
                existing = cur.fetchone()
                
                if existing:
                    if existing["global_role"] == "ROOT":
                        print(f"✓ User {email} already exists with ROOT privileges")
                        return
                    else:
                        # Upgrade existing user to ROOT
                        cur.execute("UPDATE users SET global_role = 'ROOT' WHERE email = %s", (email,))
                        conn.commit()
                        print(f"✓ Upgraded existing user {email} to ROOT admin")
                        return
                
                # Create new ROOT user
                cur.execute("""
                    INSERT INTO users (id, email, password_hash, global_role)
                    VALUES (%s, %s, %s, 'ROOT')
                """, (user_id, email, password_hash))
                conn.commit()
                print(f"✓ Created new ROOT admin user: {email}")
                
    except Exception as e:
        print(f"ERROR: Failed to create admin user: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python create_admin.py <email> <password>")
        print("Example: python create_admin.py admin@kinjar.com mySecurePassword123")
        sys.exit(1)
    
    email = sys.argv[1].strip().lower()
    password = sys.argv[2]
    
    print(f"Creating ROOT admin user: {email}")
    create_admin_user(email, password)