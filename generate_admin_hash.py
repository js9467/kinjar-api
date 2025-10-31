#!/usr/bin/env python3
"""
Generate Argon2 password hash for admin user creation.
"""
import sys
from argon2 import PasswordHasher

def generate_hash(password: str):
    if len(password) < 8:
        print("ERROR: Password must be at least 8 characters")
        sys.exit(1)
    
    ph = PasswordHasher()
    password_hash = ph.hash(password)
    
    print("=" * 60)
    print("KINJAR ADMIN SETUP")
    print("=" * 60)
    print(f"Email: slaughterbeck@gmail.com")
    print(f"Password: {password}")
    print(f"Hash: {password_hash}")
    print("=" * 60)
    print("\nSQL Command to run in your database:")
    print("=" * 60)
    print(f"""
INSERT INTO users (id, email, password_hash, global_role, created_at)
VALUES (
  gen_random_uuid(),
  'slaughterbeck@gmail.com',
  '{password_hash}',
  'ROOT',
  now()
);
""")
    print("=" * 60)
    print("\nAfter running this SQL:")
    print("1. Go to https://www.kinjar.com/login")
    print("2. Login with slaughterbeck@gmail.com")
    print(f"3. Use password: {password}")
    print("4. You'll have full admin access!")
    print("=" * 60)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python generate_admin_hash.py <password>")
        print("Example: python generate_admin_hash.py MySecurePassword123")
        sys.exit(1)
    
    password = sys.argv[1]
    generate_hash(password)