#!/usr/bin/env python3
"""
Test script to check database tables and their existence
"""

import os
import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

def test_database_tables():
    """Check what tables exist in the database"""
    print("🗄️  Testing Database Tables")
    print("=" * 50)
    
    try:
        # Database connection
        database_url = os.environ.get("DATABASE_URL")
        if not database_url:
            print("❌ DATABASE_URL environment variable not set")
            return
            
        print(f"📡 Connecting to database...")
        
        # Create connection pool
        pool = ConnectionPool(database_url, min_size=1, max_size=10)
        
        with pool.connection() as con, con.cursor(row_factory=dict_row) as cur:
            # List all tables
            print("\n📋 Listing all tables...")
            cur.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
                ORDER BY table_name;
            """)
            
            tables = cur.fetchall()
            print(f"Found {len(tables)} tables:")
            for table in tables:
                print(f"   • {table['table_name']}")
            
            # Check specifically for invitation-related tables
            print("\n🔍 Checking invitation-related tables...")
            invitation_tables = [
                'tenant_invitations',
                'family_creation_invitations',
                'invitations'
            ]
            
            for table_name in invitation_tables:
                cur.execute("""
                    SELECT COUNT(*) as exists
                    FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = %s;
                """, (table_name,))
                
                result = cur.fetchone()
                if result['exists'] > 0:
                    print(f"   ✅ {table_name} exists")
                    
                    # Get column info
                    cur.execute("""
                        SELECT column_name, data_type 
                        FROM information_schema.columns 
                        WHERE table_schema = 'public' 
                        AND table_name = %s
                        ORDER BY ordinal_position;
                    """, (table_name,))
                    
                    columns = cur.fetchall()
                    print(f"      Columns ({len(columns)}):")
                    for col in columns:
                        print(f"        - {col['column_name']} ({col['data_type']})")
                else:
                    print(f"   ❌ {table_name} does not exist")
            
            # Check for any tables with 'invitation' in the name
            print("\n🔍 Searching for any tables containing 'invitation'...")
            cur.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
                AND table_name LIKE '%invitation%'
                ORDER BY table_name;
            """)
            
            invitation_like_tables = cur.fetchall()
            if invitation_like_tables:
                print(f"   Found {len(invitation_like_tables)} tables with 'invitation' in name:")
                for table in invitation_like_tables:
                    print(f"     • {table['table_name']}")
            else:
                print("   ❌ No tables found with 'invitation' in the name")
                
    except Exception as e:
        print(f"❌ Database error: {e}")
    
    print("\n" + "=" * 50)

if __name__ == "__main__":
    test_database_tables()