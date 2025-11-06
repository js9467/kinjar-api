#!/usr/bin/env python3
"""
Diagnostic script to test comment permissions
"""
import psycopg
from psycopg.rows import dict_row
import os
import json
from datetime import datetime

# Database connection
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost/kinjar")

def get_db_connection():
    """Get database connection"""
    try:
        conn = psycopg.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"❌ Failed to connect to database: {e}")
        return None

def main():
    print("=" * 70)
    print("COMMENT PERMISSIONS DIAGNOSTIC")
    print("=" * 70)
    
    conn = get_db_connection()
    if not conn:
        return
    
    with conn.cursor(row_factory=dict_row) as cur:
        # 1. Get the slaughterbeck family ID
        print("\n📋 STEP 1: Get Slaughterbeck family")
        cur.execute("""
            SELECT id, slug, name FROM tenants WHERE slug = 'slaughterbeck'
        """)
        family = cur.fetchone()
        if not family:
            print("❌ Slaughterbeck family not found")
            return
        print(f"✅ Found: {family}")
        family_id = family['id']
        
        # 2. Get all users in the family with their roles
        print("\n👥 STEP 2: Family members and their roles")
        cur.execute("""
            SELECT u.id, u.email, u.username, tu.role
            FROM tenant_users tu
            JOIN users u ON tu.user_id = u.id
            WHERE tu.tenant_id = %s
            ORDER BY tu.role, u.username
        """, (family_id,))
        users = cur.fetchall()
        for user in users:
            print(f"  • {user['username']} ({user['email']})")
            print(f"    Role: {user['role']} | ID: {user['id']}")
        
        # 3. Get recent comments with all relevant info
        print("\n💬 STEP 3: Recent comments in the family")
        cur.execute("""
            SELECT 
                c.id,
                c.content,
                c.author_id,
                au.username as author_name,
                au.email as author_email,
                atu.role as author_role,
                c.posted_as_id,
                pau.username as posted_as_name,
                patu.role as posted_as_role,
                c.created_at,
                c.updated_at,
                p.id as post_id,
                po.username as post_author_name
            FROM content_comments c
            JOIN users au ON c.author_id = au.id
            JOIN tenant_users atu ON atu.user_id = au.id AND atu.tenant_id = %s
            LEFT JOIN users pau ON c.posted_as_id = pau.id
            LEFT JOIN tenant_users patu ON patu.user_id = pau.id AND patu.tenant_id = %s
            JOIN content_posts p ON c.post_id = p.id
            JOIN users po ON p.author_id = po.id
            WHERE p.tenant_id = %s
            ORDER BY c.created_at DESC
            LIMIT 10
        """, (family_id, family_id, family_id))
        comments = cur.fetchall()
        
        if not comments:
            print("  No comments found")
        else:
            for i, comment in enumerate(comments, 1):
                print(f"\n  Comment #{i}")
                print(f"    ID: {comment['id']}")
                print(f"    Content: '{comment['content']}'")
                print(f"    Author: {comment['author_name']} ({comment['author_email']})")
                print(f"    Author Role: {comment['author_role']}")
                if comment['posted_as_name']:
                    print(f"    Posted As: {comment['posted_as_name']} (Role: {comment['posted_as_role']})")
                print(f"    On Post by: {comment['post_author_name']}")
                print(f"    Created: {comment['created_at']}")
                if comment['updated_at'] != comment['created_at']:
                    print(f"    ⚠️  Updated: {comment['updated_at']} (EDITED!)")
        
        # 4. Test scenarios
        print("\n" + "=" * 70)
        print("🧪 PERMISSION SCENARIOS")
        print("=" * 70)
        
        if len(users) >= 2:
            user1 = users[0]
            user2 = users[1] if len(users) > 1 else users[0]
            
            print(f"\nScenario 1: {user1['username']} ({user1['role']}) trying to edit comment by {user2['username']} ({user2['role']})")
            
            # Check if there's a comment by user2
            cur.execute("""
                SELECT c.id, c.content, c.author_id, c.posted_as_id
                FROM content_comments c
                JOIN content_posts p ON c.post_id = p.id
                WHERE p.tenant_id = %s AND c.author_id = %s
                LIMIT 1
            """, (family_id, user2['id']))
            comment = cur.fetchone()
            
            if comment:
                print(f"  Found comment: {comment['id']}")
                print(f"  Author: {user2['id']} (username: {user2['username']})")
                print(f"  Posted As: {comment.get('posted_as_id', 'Direct')}")
                
                # Determine if edit should be allowed
                if user1['id'] == user2['id']:
                    print(f"  ✅ SHOULD ALLOW: Same user editing their own comment")
                elif user1['role'] in ['ADMIN', 'OWNER']:
                    print(f"  ✅ SHOULD ALLOW: {user1['role']} can edit any comment")
                elif user1['role'] in ['ADULT', 'MEMBER'] and user2['role'].startswith('CHILD'):
                    print(f"  ✅ SHOULD ALLOW: Adult can edit child comment")
                elif user1['role'] in ['ADULT', 'MEMBER'] and user2['role'] in ['ADULT', 'MEMBER']:
                    print(f"  ❌ SHOULD DENY: Adult cannot edit other adult's comment")
                elif user2['role'].startswith('CHILD') and user1['role'].startswith('CHILD'):
                    print(f"  ❌ SHOULD DENY: Child cannot edit other child's comment")
            else:
                print("  No comments found by this user to test")
    
    conn.close()
    print("\n" + "=" * 70)

if __name__ == "__main__":
    main()
