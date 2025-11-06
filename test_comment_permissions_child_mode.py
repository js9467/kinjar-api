import os
import unittest
import uuid
import psycopg
from datetime import datetime, timezone
from psycopg_pool import ConnectionPool

class TestCommentPermissionsWithChildMode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Get database connection from env var or use test db
        cls.db_url = os.getenv("DATABASE_URL", "postgresql://localhost/kinjar_test")
        cls.pool = ConnectionPool(cls.db_url)

    def setUp(self):
        # Create test data for each test
        self.tenant_id = str(uuid.uuid4())
        self.adult_id = str(uuid.uuid4()) 
        self.child1_id = str(uuid.uuid4())  # First child profile
        self.child2_id = str(uuid.uuid4())  # Second child profile
        self.post_id = str(uuid.uuid4())
        self.comment_id = str(uuid.uuid4())
        
        with self.pool.connection() as con:
            with con.cursor() as cur:
                # Create test tenant
                cur.execute("""
                    INSERT INTO tenants (id, slug, name)
                    VALUES (%s, 'test-family', 'Test Family')
                """, (self.tenant_id,))
                
                # Create adult user
                cur.execute("""
                    INSERT INTO users (id, email, password_hash, global_role)
                    VALUES (%s, 'test_adult@test.com', 'hash', 'USER')
                """, (self.adult_id,))
                
                # Create child profiles (these are also users but represent child profiles)
                cur.execute("""
                    INSERT INTO users (id, email, password_hash, global_role)
                    VALUES (%s, 'child1@test.com', 'hash', 'USER')
                """, (self.child1_id,))
                
                cur.execute("""
                    INSERT INTO users (id, email, password_hash, global_role)
                    VALUES (%s, 'child2@test.com', 'hash', 'USER')
                """, (self.child2_id,))
                
                # Add adult to tenant
                cur.execute("""
                    INSERT INTO tenant_users (user_id, tenant_id, role)
                    VALUES (%s, %s, 'ADULT')
                """, (self.adult_id, self.tenant_id))
                
                # Add child profiles to tenant
                cur.execute("""
                    INSERT INTO tenant_users (user_id, tenant_id, role)
                    VALUES (%s, %s, 'CHILD_10_14')
                """, (self.child1_id, self.tenant_id))
                
                cur.execute("""
                    INSERT INTO tenant_users (user_id, tenant_id, role)
                    VALUES (%s, %s, 'CHILD_10_14')
                """, (self.child2_id, self.tenant_id))
                
                # Create test post
                cur.execute("""
                    INSERT INTO content_posts (id, tenant_id, author_id, title, content, status)
                    VALUES (%s, %s, %s, 'Test Post', 'Test content', 'published')
                """, (self.post_id, self.tenant_id, self.adult_id))
                
                # Create test comment as child1 (posted by adult acting as child1)
                cur.execute("""
                    INSERT INTO content_comments (id, post_id, author_id, posted_as_id, content)
                    VALUES (%s, %s, %s, %s, 'Test comment')
                """, (self.comment_id, self.post_id, self.adult_id, self.child1_id))

    def tearDown(self):
        # Clean up test data
        with self.pool.connection() as con:
            with con.cursor() as cur:
                cur.execute("DELETE FROM content_comments WHERE post_id = %s", (self.post_id,))
                cur.execute("DELETE FROM content_posts WHERE id = %s", (self.post_id,))
                cur.execute("DELETE FROM tenant_users WHERE tenant_id = %s", (self.tenant_id,))
                cur.execute("DELETE FROM users WHERE id IN (%s, %s, %s)", 
                          (self.adult_id, self.child1_id, self.child2_id))
                cur.execute("DELETE FROM tenants WHERE id = %s", (self.tenant_id,))

    def test_adult_can_delete_comment_made_as_child(self):
        """Test that an adult can delete a comment they made while acting as a child"""
        with self.pool.connection() as con:
            with con.cursor() as cur:
                # Simulate adult trying to delete comment they made as child1
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
                    AND (cc.author_id = %s OR cc.posted_as_id = %s)
                    AND ur.role = 'ADULT'
                    RETURNING cc.id
                """, (self.comment_id, self.adult_id, self.adult_id, self.child1_id))
                deleted = cur.fetchone()
                self.assertIsNotNone(deleted, "Adult should be able to delete comment made as child")

    def test_adult_acting_as_different_child_cannot_delete_other_child_comment(self):
        """Test that an adult acting as child2 cannot delete child1's comment"""
        with self.pool.connection() as con:
            with con.cursor() as cur:
                # Create comment as child1
                comment_id = str(uuid.uuid4())
                cur.execute("""
                    INSERT INTO content_comments (id, post_id, author_id, posted_as_id, content)
                    VALUES (%s, %s, %s, %s, 'Child 1 comment')
                """, (comment_id, self.post_id, self.adult_id, self.child1_id))
                
                # Try to delete as child2
                cur.execute("""
                    WITH comment_info AS (
                        SELECT c.*, p.tenant_id
                        FROM content_comments c 
                        JOIN content_posts p ON c.post_id = p.id
                        WHERE c.id = %s
                    )
                    DELETE FROM content_comments cc
                    USING comment_info ci
                    WHERE cc.id = ci.id
                    AND cc.posted_as_id = %s  -- Attempting as child2
                    RETURNING cc.id
                """, (comment_id, self.child2_id))
                deleted = cur.fetchone()
                self.assertIsNone(deleted, "Adult acting as child2 should not be able to delete child1's comment")

    def test_adult_acting_as_child_can_delete_own_comment(self):
        """Test that an adult acting as a child can delete their own comment made as that child"""
        with self.pool.connection() as con:
            with con.cursor() as cur:
                # Create comment as child1
                comment_id = str(uuid.uuid4())
                cur.execute("""
                    INSERT INTO content_comments (id, post_id, author_id, posted_as_id, content)
                    VALUES (%s, %s, %s, %s, 'Child 1 comment')
                """, (comment_id, self.post_id, self.adult_id, self.child1_id))
                
                # Try to delete as same child
                cur.execute("""
                    WITH comment_info AS (
                        SELECT c.*, p.tenant_id
                        FROM content_comments c 
                        JOIN content_posts p ON c.post_id = p.id
                        WHERE c.id = %s
                    )
                    DELETE FROM content_comments cc
                    USING comment_info ci
                    WHERE cc.id = ci.id
                    AND cc.posted_as_id = %s  -- Same child
                    RETURNING cc.id
                """, (comment_id, self.child1_id))
                deleted = cur.fetchone()
                self.assertIsNotNone(deleted, "Adult acting as child1 should be able to delete their own comment made as child1")

if __name__ == '__main__':
    unittest.main()