"""Polyglot Syntax-Aware Code & Policy Chunker.

Supports intelligent block segmentation, symbol extraction, and scope preservation across:
Python, JavaScript/TypeScript, Dart/Flutter, Java, Kotlin, C#/.NET, C/C++, Rust, Go,
Ruby, PHP, Swift, Scala, SQL, HTML/Web, and Markdown/Policy documents.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class CodeChunk:
    """A semantic chunk of code or policy documentation."""

    chunk_id: str
    file_path: str
    language: str
    symbol_name: str
    chunk_type: str  # 'function', 'class', 'struct', 'section', 'block', 'config'
    start_line: int
    end_line: int
    content: str
    context_header: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)


# Extension to language mapping
EXTENSION_LANGUAGE_MAP: Dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".dart": "dart",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "csharp",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".rs": "rust",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".phtml": "php",
    ".swift": "swift",
    ".scala": "scala",
    ".sc": "scala",
    ".sql": "sql",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".md": "markdown",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".properties": "properties",
    ".env": "env",
}


# Comment and block boundaries per language
COMMENT_STYLES: Dict[str, Dict[str, str]] = {
    "python": {"single": "#", "multi_start": '"""', "multi_end": '"""'},
    "ruby": {"single": "#", "multi_start": "=begin", "multi_end": "=end"},
    "sql": {"single": "--", "multi_start": "/*", "multi_end": "*/"},
    "html": {"single": "", "multi_start": "<!--", "multi_end": "-->"},
    "default": {"single": "//", "multi_start": "/*", "multi_end": "*/"},
}


def is_comment_line(line: str, language: str = "default") -> bool:
    """Check if a trimmed line is a single-line comment in the specified language."""
    trimmed = line.strip()
    if not trimmed:
        return False
    if language in ("python", "ruby", "yaml", "yml", "env", "properties"):
        return trimmed.startswith("#")
    if language == "sql":
        return trimmed.startswith("--") or trimmed.startswith("/*")
    if language == "html":
        return trimmed.startswith("<!--")
    # C-style languages (Java, C#, C, C++, Rust, Go, JS, TS, Dart, Swift, Kotlin, Scala, PHP)
    return trimmed.startswith("//") or trimmed.startswith("/*") or trimmed.startswith("*")


def strip_comments_and_strings(code: str, language: str = "default") -> str:
    """Remove comments and replace string literal contents with empty quotes for syntax parsing."""
    if language == "python":
        pattern = r'(\"\"\"[\s\S]*?\"\"\"|\'\'\'[\s\S]*?\'\'\'|\"[^\"\n]*\"|\'[^\'\n]*\'|#.*)'
    elif language in ("ruby",):
        pattern = r'(=begin[\s\S]*?=end|\"[^\"\n]*\"|\'[^\'\n]*\'|#.*)'
    elif language == "html":
        pattern = r'(<!--[\s\S]*?-->|\"[^\"\n]*\"|\'[^\'\n]*\')'
    elif language == "sql":
        pattern = r'(/\*[\s\S]*?\*/|\"[^\"\n]*\"|\'[^\'\n]*\'|--.*)'
    else:
        # C-style (C, C++, Java, C#, Go, Rust, Swift, Kotlin, Scala, JS, TS, PHP, Dart)
        pattern = r'(/\*[\s\S]*?\*/|//.*|\"(?:\\.|[^\"\\])*\"|\'(?:\\.|[^\'\\])*\')'

    def replacer(match):
        s = match.group(0)
        if s.startswith(("//", "#", "--", "/*", "<!--", "=begin", '"""', "'''")):
            return "\n" * s.count("\n")
        elif s.startswith('"') or s.startswith("'"):
            return '""' + ("\n" * s.count("\n"))
        return s

    return re.sub(pattern, replacer, code)


class PolyglotChunker:
    """Semantic syntax-aware chunker for multi-language codebases and policy rulebooks."""

    def __init__(self, target_chunk_lines: int = 50, overlap_lines: int = 10):
        self.target_chunk_lines = target_chunk_lines
        self.overlap_lines = overlap_lines

    def detect_language(self, file_path: Path) -> str:
        """Identify language from file extension or fallback."""
        ext = file_path.suffix.lower()
        return EXTENSION_LANGUAGE_MAP.get(ext, "text")

    def chunk_file(self, file_path: Path) -> List[CodeChunk]:
        """Read and chunk a file based on its syntax."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            return self.chunk_text(content, file_path=str(file_path))
        except Exception:
            return []

    def chunk_text(self, text: str, file_path: str = "snippet") -> List[CodeChunk]:
        """Chunk raw content using language-specific strategies."""
        path_obj = Path(file_path)
        language = self.detect_language(path_obj)

        if language == "markdown":
            return self._chunk_markdown(text, file_path)
        elif language == "python":
            return self._chunk_python(text, file_path)
        elif language in ("javascript", "typescript", "dart", "java", "kotlin", "csharp", "c", "cpp", "rust", "go", "swift", "scala", "php"):
            return self._chunk_c_style(text, file_path, language)
        elif language == "sql":
            return self._chunk_sql(text, file_path)
        else:
            return self._chunk_sliding_window(text, file_path, language)

    # -----------------------------------------------------------------------
    # Markdown & Regulatory Policy Chunker
    # -----------------------------------------------------------------------
    def _chunk_markdown(self, text: str, file_path: str) -> List[CodeChunk]:
        chunks: List[CodeChunk] = []
        lines = text.split("\n")
        current_section = "Introduction"
        current_header = ""
        buffer: List[str] = []
        start_line = 1

        for idx, line in enumerate(lines):
            line_num = idx + 1
            header_match = re.match(r"^(#{1,4})\s+(.+)$", line)

            if header_match:
                if buffer:
                    content_str = "\n".join(buffer).strip()
                    if content_str:
                        chunks.append(
                            CodeChunk(
                                chunk_id=f"chk-{uuid.uuid4().hex[:8]}",
                                file_path=file_path,
                                language="markdown",
                                symbol_name=current_section,
                                chunk_type="section",
                                start_line=start_line,
                                end_line=line_num - 1,
                                content=content_str,
                                context_header=current_header,
                            )
                        )
                    buffer = []
                current_section = header_match.group(2).strip()
                current_header = line.strip()
                start_line = line_num

            buffer.append(line)

        if buffer:
            content_str = "\n".join(buffer).strip()
            if content_str:
                chunks.append(
                    CodeChunk(
                        chunk_id=f"chk-{uuid.uuid4().hex[:8]}",
                        file_path=file_path,
                        language="markdown",
                        symbol_name=current_section,
                        chunk_type="section",
                        start_line=start_line,
                        end_line=len(lines),
                        content=content_str,
                        context_header=current_header,
                    )
                )

        return chunks

    # -----------------------------------------------------------------------
    # Python Indentation-Aware Chunker
    # -----------------------------------------------------------------------
    def _chunk_python(self, text: str, file_path: str) -> List[CodeChunk]:
        chunks: List[CodeChunk] = []
        lines = text.split("\n")
        buffer: List[str] = []
        start_line = 1
        current_symbol = "module"
        current_type = "module"
        active_class = ""

        def flush(end_idx: int):
            nonlocal buffer, start_line, current_symbol, current_type
            content_str = "\n".join(buffer).strip()
            if content_str:
                header = f"class {active_class}" if active_class else ""
                chunks.append(
                    CodeChunk(
                        chunk_id=f"chk-{uuid.uuid4().hex[:8]}",
                        file_path=file_path,
                        language="python",
                        symbol_name=current_symbol,
                        chunk_type=current_type,
                        start_line=start_line,
                        end_line=end_idx,
                        content=content_str,
                        context_header=header,
                    )
                )
            buffer = []

        for idx, line in enumerate(lines):
            line_num = idx + 1
            # Top-level class
            class_m = re.match(r"^class\s+([A-Za-z0-9_]+)", line)
            # Function or method
            fn_m = re.match(r"^(\s*)def\s+([A-Za-z0-9_]+)", line)

            if class_m:
                flush(line_num - 1)
                active_class = class_m.group(1)
                current_symbol = active_class
                current_type = "class"
                start_line = line_num

            elif fn_m and len(fn_m.group(1)) == 0:  # Top-level function
                flush(line_num - 1)
                active_class = ""
                current_symbol = fn_m.group(2)
                current_type = "function"
                start_line = line_num

            elif fn_m and len(fn_m.group(1)) > 0 and len(buffer) >= self.target_chunk_lines:
                flush(line_num - 1)
                current_symbol = f"{active_class}.{fn_m.group(2)}" if active_class else fn_m.group(2)
                current_type = "method"
                start_line = line_num

            buffer.append(line)

        flush(len(lines))
        return chunks if chunks else self._chunk_sliding_window(text, file_path, "python")

    # -----------------------------------------------------------------------
    # C-Style Braced Polyglot Chunker (JS/TS, Dart, Java, C#, C/C++, Rust, Go, etc.)
    # -----------------------------------------------------------------------
    def _chunk_c_style(self, text: str, file_path: str, language: str) -> List[CodeChunk]:
        chunks: List[CodeChunk] = []
        lines = text.split("\n")

        # Top-level symbol detector patterns
        symbol_patterns = [
            # Java / C# / TS / Dart / Kotlin classes, interfaces, structs, enums
            (r"\b(class|interface|struct|enum|trait|impl|record)\s+([A-Za-z0-9_]+)", "class"),
            # Functions in Go, Rust, Swift, Kotlin, Dart, JS/TS, C/C++
            (r"\b(func|fn|fun|function|def)\s+([A-Za-z0-9_]+)", "function"),
            # Typical method declaration: public void myMethod(...), Task<int> Run(...)
            (r"^\s*(public|private|protected|static|async)?\s*(void|int|string|bool|Task|Future|Widget|Result|[\w<>\[\]]+)\s+([A-Za-z0-9_]+)\s*\(", "method"),
        ]

        buffer: List[str] = []
        start_line = 1
        current_symbol = "global"
        current_type = "block"
        current_header = ""
        in_block_comment = False

        def flush(end_idx: int):
            nonlocal buffer, start_line, current_symbol, current_type, current_header
            content_str = "\n".join(buffer).strip()
            if content_str:
                comment_lines = sum(1 for l in buffer if is_comment_line(l, language))
                code_lines = len(buffer) - comment_lines
                chunks.append(
                    CodeChunk(
                        chunk_id=f"chk-{uuid.uuid4().hex[:8]}",
                        file_path=file_path,
                        language=language,
                        symbol_name=current_symbol,
                        chunk_type=current_type,
                        start_line=start_line,
                        end_line=end_idx,
                        content=content_str,
                        context_header=current_header,
                        metadata={
                            "language": language,
                            "has_comments": str(comment_lines > 0),
                            "comment_lines": str(comment_line_count) if "comment_line_count" in locals() else str(comment_lines),
                            "code_lines": str(code_lines),
                        },
                    )
                )
            buffer = []

        for idx, line in enumerate(lines):
            line_num = idx + 1
            trimmed = line.strip()

            # Track multi-line comment state
            if "/*" in line and "*/" not in line:
                in_block_comment = True
            elif "*/" in line:
                in_block_comment = False

            is_cmt = in_block_comment or is_comment_line(line, language)

            # Only scan for symbol declarations if NOT in comments or strings
            if not is_cmt:
                clean_line = strip_comments_and_strings(line, language)
                for pat, ctype in symbol_patterns:
                    m = re.search(pat, clean_line)
                    if m:
                        # If buffer is large enough or new major declaration
                        if len(buffer) >= 20 or ctype == "class":
                            flush(line_num - 1)
                            sym = m.group(len(m.groups()))  # last group is name
                            current_symbol = sym
                            current_type = ctype
                            current_header = line.strip()
                            start_line = line_num
                            break

            buffer.append(line)
            # If buffer exceeded max lines, flush cleanly
            if len(buffer) >= self.target_chunk_lines:
                flush(line_num)
                start_line = line_num + 1
                current_symbol = "block"
                current_type = "block"

        flush(len(lines))
        return chunks if chunks else self._chunk_sliding_window(text, file_path, language)

    # -----------------------------------------------------------------------
    # SQL Statement Chunker
    # -----------------------------------------------------------------------
    def _chunk_sql(self, text: str, file_path: str) -> List[CodeChunk]:
        chunks: List[CodeChunk] = []
        lines = text.split("\n")
        buffer: List[str] = []
        start_line = 1
        current_statement = "sql_statement"

        for idx, line in enumerate(lines):
            line_num = idx + 1
            stmt_match = re.match(r"^\s*(CREATE|ALTER|DROP|INSERT|SELECT|UPDATE|DELETE)\s+([A-Za-z0-9_\.]+)", line, re.IGNORECASE)
            if stmt_match:
                current_statement = f"{stmt_match.group(1).upper()} {stmt_match.group(2)}"

            buffer.append(line)

            # Semicolon terminating statement
            if ";" in line and len(buffer) >= 5:
                content_str = "\n".join(buffer).strip()
                if content_str:
                    chunks.append(
                        CodeChunk(
                            chunk_id=f"chk-{uuid.uuid4().hex[:8]}",
                            file_path=file_path,
                            language="sql",
                            symbol_name=current_statement,
                            chunk_type="statement",
                            start_line=start_line,
                            end_line=line_num,
                            content=content_str,
                        )
                    )
                buffer = []
                start_line = line_num + 1

        if buffer:
            content_str = "\n".join(buffer).strip()
            if content_str:
                chunks.append(
                    CodeChunk(
                        chunk_id=f"chk-{uuid.uuid4().hex[:8]}",
                        file_path=file_path,
                        language="sql",
                        symbol_name=current_statement,
                        chunk_type="statement",
                        start_line=start_line,
                        end_line=len(lines),
                        content=content_str,
                    )
                )

        return chunks

    # -----------------------------------------------------------------------
    # Sliding Window Fallback
    # -----------------------------------------------------------------------
    def _chunk_sliding_window(self, text: str, file_path: str, language: str) -> List[CodeChunk]:
        chunks: List[CodeChunk] = []
        lines = text.split("\n")
        step = max(1, self.target_chunk_lines - self.overlap_lines)

        for i in range(0, len(lines), step):
            window = lines[i : i + self.target_chunk_lines]
            content = "\n".join(window).strip()
            if not content:
                continue
            chunks.append(
                CodeChunk(
                    chunk_id=f"chk-{uuid.uuid4().hex[:8]}",
                    file_path=file_path,
                    language=language,
                    symbol_name=f"lines_{i+1}_{i+len(window)}",
                    chunk_type="window",
                    start_line=i + 1,
                    end_line=i + len(window),
                    content=content,
                )
            )
        return chunks
