import os
import unittest
import uuid
import psycopg
from datetime import datetime, timezone
from psycopg_pool import ConnectionPool

class TestCommentPermissions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Get database connection from env var or use test db
        cls.db_url = os.getenv("DATABASE_URL", "postgresql://localhost/kinjar_test")
        cls.pool = ConnectionPool(cls.db_url)

    def setUp(self):
        # Create test data for each test
        self.tenant_id = str(uuid.uuid4())
        self.adult_id = str(uuid.uuid4()) 
        self.child_id = str(uuid.uuid4())
        self.post_id = str(uuid.uuid4())
        self.comment_id = str(uuid.uuid4())
        
        with self.pool.connection() as con:
            with con.cursor() as cur:
                # Create test tenant
                cur.execute("""
                    INSERT INTO tenants (id, slug, name)
                    VALUES (%s, 'test-family', 'Test Family')
                """, (self.tenant_id,))
                
                # Create test users (adult and child)
                cur.execute("""
                    INSERT INTO users (id, email, password_hash, global_role)
                    VALUES (%s, 'test_adult@test.com', 'hash', 'USER')
                """, (self.adult_id,))
                
                cur.execute("""
                    INSERT INTO users (id, email, password_hash, global_role)
                    VALUES (%s, 'test_child@test.com', 'hash', 'USER')
                """, (self.child_id,))
                
                # Add users to tenant with roles
                cur.execute("""
                    INSERT INTO tenant_users (user_id, tenant_id, role)
                    VALUES (%s, %s, 'ADULT')
                """, (self.adult_id, self.tenant_id))
                
                cur.execute("""
                    INSERT INTO tenant_users (user_id, tenant_id, role)
                    VALUES (%s, %s, 'CHILD_10_14')
                """, (self.child_id, self.tenant_id))
                
                # Create test post
                cur.execute("""
                    INSERT INTO content_posts (id, tenant_id, author_id, title, content, status)
                    VALUES (%s, %s, %s, 'Test Post', 'Test content', 'published')
                """, (self.post_id, self.tenant_id, self.adult_id))
                
                # Create test comment
                cur.execute("""
                    INSERT INTO content_comments (id, post_id, author_id, content)
                    VALUES (%s, %s, %s, 'Test comment')
                """, (self.comment_id, self.post_id, self.child_id))

    def tearDown(self):
        # Clean up test data
        with self.pool.connection() as con:
            with con.cursor() as cur:
                cur.execute("DELETE FROM content_comments WHERE post_id = %s", (self.post_id,))
                cur.execute("DELETE FROM content_posts WHERE id = %s", (self.post_id,))
                cur.execute("DELETE FROM tenant_users WHERE tenant_id = %s", (self.tenant_id,))
                cur.execute("DELETE FROM users WHERE id IN (%s, %s)", (self.adult_id, self.child_id))
                cur.execute("DELETE FROM tenants WHERE id = %s", (self.tenant_id,))

    def test_adult_can_delete_child_comment(self):
        """Test that an adult can delete a child's comment"""
        with self.pool.connection() as con:
            with con.cursor() as cur:
                # Simulate adult trying to delete child's comment
                cur.execute("""
                    WITH comment_info AS (
                        SELECT c.*, p.tenant_id
                        FROM content_comments c 
                        JOIN content_posts p ON c.post_id = p.id
                        WHERE c.id = %s
                    ),
                    user_role AS (
                        SELECT tu.role
                        FROM tenant_users tu
                        JOIN comment_info ci ON tu.tenant_id = ci.tenant_id
                        WHERE tu.user_id = %s
                    )
                    DELETE FROM content_comments cc
                    USING comment_info ci, user_role ur
                    WHERE cc.id = ci.id
                    AND ur.role = 'ADULT'
                    RETURNING cc.id
                """, (self.comment_id, self.adult_id))
                deleted = cur.fetchone()
                self.assertIsNotNone(deleted, "Adult should be able to delete child's comment")

    def test_child_cannot_delete_other_child_comment(self):
        """Test that a child cannot delete another child's comment"""
        other_child_id = str(uuid.uuid4())
        other_comment_id = str(uuid.uuid4())
        
        with self.pool.connection() as con:
            with con.cursor() as cur:
                # Create another child user
                cur.execute("""
                    INSERT INTO users (id, email, password_hash, global_role)
                    VALUES (%s, 'other_child@test.com', 'hash', 'USER')
                """, (other_child_id,))
                
                cur.execute("""
                    INSERT INTO tenant_users (user_id, tenant_id, role)
                    VALUES (%s, %s, 'CHILD_10_14')
                """, (other_child_id, self.tenant_id))
                
                # Create comment by the other child
                cur.execute("""
                    INSERT INTO content_comments (id, post_id, author_id, content)
                    VALUES (%s, %s, %s, 'Other child comment')
                """, (other_comment_id, self.post_id, other_child_id))
                
                # Try to delete other child's comment
                cur.execute("""
                    WITH comment_info AS (
                        SELECT c.*, p.tenant_id
                        FROM content_comments c 
                        JOIN content_posts p ON c.post_id = p.id
                        WHERE c.id = %s
                    ),
                    user_role AS (
                        SELECT tu.role, tu.user_id
                        FROM tenant_users tu
                        JOIN comment_info ci ON tu.tenant_id = ci.tenant_id
                        WHERE tu.user_id = %s
                    )
                    DELETE FROM content_comments cc
                    USING comment_info ci, user_role ur
                    WHERE cc.id = ci.id
                    AND ur.role LIKE 'CHILD_%'
                    AND cc.author_id = ur.user_id
                    RETURNING cc.id
                """, (other_comment_id, self.child_id))
                deleted = cur.fetchone()
                self.assertIsNone(deleted, "Child should not be able to delete another child's comment")

    def test_child_can_delete_own_comment(self):
        """Test that a child can delete their own comment"""
        with self.pool.connection() as con:
            with con.cursor() as cur:
                cur.execute("""
                    WITH comment_info AS (
                        SELECT c.*, p.tenant_id
                        FROM content_comments c 
                        JOIN content_posts p ON c.post_id = p.id
                        WHERE c.id = %s
                    ),
                    user_role AS (
                        SELECT tu.role, tu.user_id
                        FROM tenant_users tu
                        JOIN comment_info ci ON tu.tenant_id = ci.tenant_id
                        WHERE tu.user_id = %s
                    )
                    DELETE FROM content_comments cc
                    USING comment_info ci, user_role ur
                    WHERE cc.id = ci.id
                    AND ur.role LIKE 'CHILD_%'
                    AND cc.author_id = ur.user_id
                    RETURNING cc.id
                """, (self.comment_id, self.child_id))
                deleted = cur.fetchone()
                self.assertIsNotNone(deleted, "Child should be able to delete their own comment")

if __name__ == '__main__':
    unittest.main()