"""Tests for Polyglot Chunker."""

from pathlib import Path
from cortex_rag.polyglot_chunker import PolyglotChunker


def test_chunk_markdown_policies():
    chunker = PolyglotChunker()
    md_content = """# GDPR Compliance Rulebook
## Article 8: Children's Privacy
Information society services offered to children must have age gate.

## Article 17: Right to Erasure
User data must be erased upon request without undue delay.
"""
    chunks = chunker.chunk_text(md_content, "policies/gdpr.md")
    assert len(chunks) >= 2
    assert any("Article 8" in c.symbol_name for c in chunks)
    assert any("Article 17" in c.symbol_name for c in chunks)


def test_chunk_java_class():
    chunker = PolyglotChunker(target_chunk_lines=10)
    java_code = """package com.example;

public class PaymentService {
    public void processPayment(String card) {
        System.out.println("Processing: " + card);
    }
}
"""
    chunks = chunker.chunk_text(java_code, "PaymentService.java")
    assert len(chunks) >= 1
    assert any(c.language == "java" for c in chunks)


def test_chunk_rust_file():
    chunker = PolyglotChunker()
    rust_code = """pub struct AuthManager {
    token: String,
}

impl AuthManager {
    pub fn new() -> Self {
        Self { token: String::new() }
    }
}
"""
    chunks = chunker.chunk_text(rust_code, "auth.rs")
    assert len(chunks) >= 1
    assert any(c.language == "rust" for c in chunks)


def test_chunk_sql_statements():
    chunker = PolyglotChunker()
    sql_code = """CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL
);

ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
"""
    chunks = chunker.chunk_text(sql_code, "schema.sql")
    assert len(chunks) >= 1
    assert any(c.language == "sql" for c in chunks)


def test_chunk_comments_and_strings_detection():
    from cortex_rag.polyglot_chunker import is_comment_line, strip_comments_and_strings

    # Verify single-line comment checks across languages
    assert is_comment_line("// this is a comment", "java")
    assert is_comment_line("# python comment", "python")
    assert is_comment_line("-- sql comment", "sql")
    assert is_comment_line("<!-- html comment -->", "html")
    assert not is_comment_line("int x = 42;", "c")

    # Verify comments inside string vs real code
    code = 'String s = "/* fake comment */"; // real comment\nint a = 1;'
    cleaned = strip_comments_and_strings(code, "java")
    assert "// real comment" not in cleaned

    # Verify chunker tracks comments metadata
    chunker = PolyglotChunker()
    commented_java = """// Copyright 2026
// All rights reserved
package com.demo;

public class SecureService {
    // Comment line
    public void execute() {
        System.out.println("Done");
    }
}"""
    chunks = chunker.chunk_text(commented_java, "SecureService.java")
    assert len(chunks) >= 1
    assert any(c.metadata.get("has_comments") == "True" for c in chunks)

