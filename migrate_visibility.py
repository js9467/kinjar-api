#!/usr/bin/env python3
"""
Migration script to add visibility column to content_posts table
This is a safe migration that can be run multiple times
"""

import os
import psycopg2
from urllib.parse import urlparse
import sys

def main():
    try:
        # Get database URL from environment
        database_url = os.getenv('DATABASE_URL')
        if not database_url:
            print("ERROR: DATABASE_URL environment variable not found")
            sys.exit(1)
            
        print(f"Connecting to database...")
        url = urlparse(database_url)
        
        con = psycopg2.connect(
            host=url.hostname,
            port=url.port,
            user=url.username, 
            password=url.password,
            database=url.path[1:] if url.path else 'kinjar'
        )
        
        with con.cursor() as cur:
            print("Checking if visibility column exists...")
            cur.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'content_posts' AND column_name = 'visibility'
            """)
            exists = cur.fetchone()
            
            if exists:
                print("✓ Visibility column already exists")
            else:
                print("Adding visibility column...")
                cur.execute("""
                    ALTER TABLE content_posts 
                    ADD COLUMN visibility text DEFAULT 'family'
                """)
                print("✓ Visibility column added")
                
                print("Updating existing rows...")
                cur.execute("""
                    UPDATE content_posts 
                    SET visibility = CASE 
                        WHEN is_public = true THEN 'public'
                        ELSE 'family'
                    END
                    WHERE visibility IS NULL
                """)
                affected = cur.rowcount
                print(f"✓ Updated {affected} existing rows")
            
            print("Creating content_visibility table if not exists...")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS content_visibility (
                    id SERIAL PRIMARY KEY,
                    post_id UUID REFERENCES content_posts(id) ON DELETE CASCADE,
                    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
                    granted_by UUID REFERENCES users(id),
                    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(post_id, tenant_id)
                )
            """)
            print("✓ Content visibility table ready")
            
            print("Creating indexes...")
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_content_visibility_tenant_granted
                ON content_visibility (tenant_id, granted_at DESC)
            """)
            print("✓ Indexes created")
            
        con.commit()
        print("✅ Migration completed successfully!")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        sys.exit(1)
    finally:
        if 'con' in locals():
            con.close()

if __name__ == "__main__":
    main()