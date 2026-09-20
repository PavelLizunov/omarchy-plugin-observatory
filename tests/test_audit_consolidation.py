"""test_audit_consolidation.py - Unit tests for audit report comment resolution."""

import sqlite3
import unittest
from tools.consolidate_audit_results import find_precise_comment_id


class TestAuditConsolidationResolver(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("""
            CREATE TABLE comments (
                id INTEGER PRIMARY KEY,
                issue_number INTEGER,
                user TEXT,
                body TEXT
            )
        """)

    def tearDown(self):
        self.conn.close()

    def test_exact_unique_match(self):
        """Unique comment matching text snippet should return the exact comment ID."""
        self.conn.execute("INSERT INTO comments VALUES (101, 500, 'HANCORE-linux', 'Please remove root AGENTS.md from distributable checkout.')")
        self.conn.execute("INSERT INTO comments VALUES (102, 500, 'HANCORE-linux', 'LGTM on the latest commit.')")
        self.conn.commit()

        cid = find_precise_comment_id(self.conn, 500, "HANCORE-linux", "remove root AGENTS.md from distributable checkout")
        self.assertEqual(cid, 101)

    def test_substring_tie_rejection(self):
        """When multiple comments match the exact same substring, resolver must reject tie and return None."""
        self.conn.execute("INSERT INTO comments VALUES (201, 600, 'HANCORE-linux', 'Security review blocked: remove AGENTS.md')")
        self.conn.execute("INSERT INTO comments VALUES (202, 600, 'HANCORE-linux', 'Security review blocked: remove AGENTS.md')")
        self.conn.commit()

        cid = find_precise_comment_id(self.conn, 600, "HANCORE-linux", "Security review blocked: remove AGENTS.md")
        self.assertIsNone(cid)

    def test_scored_overlap_tie_rejection(self):
        """When multiple comments share the exact same highest word overlap score (>= 5 words), resolver must reject tie."""
        self.conn.execute("INSERT INTO comments VALUES (203, 650, 'HANCORE-linux', 'directive instructions checkout distributable security violation')")
        self.conn.execute("INSERT INTO comments VALUES (204, 650, 'HANCORE-linux', 'directive instructions checkout distributable security problem')")
        self.conn.commit()

        # Both match 5 words: directive, instructions, checkout, distributable, security
        cid = find_precise_comment_id(self.conn, 650, "HANCORE-linux", "directive instructions checkout distributable security finding")
        self.assertIsNone(cid, "Equal word overlap tie must be rejected")

    def test_word_count_threshold_boundary(self):
        """Word overlap requires >= 5 words; 4 matching words must return None."""
        self.conn.execute("INSERT INTO comments VALUES (205, 660, 'HANCORE-linux', 'alpha beta gamma delta epsilon')")
        self.conn.commit()

        # Only 4 words overlap (alpha beta gamma delta)
        cid = find_precise_comment_id(self.conn, 660, "HANCORE-linux", "alpha beta gamma delta other words here")
        self.assertIsNone(cid, "4 words overlap is below the >= 5 threshold and must return None")

        # 5 words overlap (alpha beta gamma delta epsilon)
        cid = find_precise_comment_id(self.conn, 660, "HANCORE-linux", "alpha beta gamma delta epsilon other words here")
        self.assertEqual(cid, 205, "5 words overlap meets the threshold")

    def test_low_confidence_unlinked(self):
        """Low confidence overlap or missing keywords must return None (unlinked)."""
        self.conn.execute("INSERT INTO comments VALUES (301, 700, 'HANCORE-linux', 'Thanks for the update.')")
        self.conn.commit()

        cid = find_precise_comment_id(self.conn, 700, "HANCORE-linux", "completely unrelated objection text about memory leaks")
        self.assertIsNone(cid)


if __name__ == "__main__":
    unittest.main()
