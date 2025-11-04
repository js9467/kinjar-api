import psycopg
import argparse
from argon2 import PasswordHasher
import os

# Database connection
DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    print('DATABASE_URL environment variable not set')
    exit(1)

# Initialize password hasher
ph = PasswordHasher()

def reset_password(email, new_password):
    try:
        # Hash the new password
        password_hash = ph.hash(new_password)
        
        # Connect to database
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                # Update user password
                cur.execute(
                    'UPDATE users SET password_hash = %s WHERE email = %s',
                    (password_hash, email)
                )
                
                if cur.rowcount == 0:
                    print(f'No user found with email: {email}')
                    return False
                
                conn.commit()
                print(f'Password reset successfully for {email}')
                return True
                
    except Exception as e:
        print(f'Error resetting password: {e}')
        return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Reset user password')
    parser.add_argument('email', help='User email')
    parser.add_argument('password', help='New password')
    
    args = parser.parse_args()
    reset_password(args.email, args.password)
