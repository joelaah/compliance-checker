"""Configuration module for Cortex-Compliance."""

from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables and defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Local Ollama Configuration
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:3b"
    ollama_embed_model: str = "nomic-embed-text"

    # Supabase Configuration (pgvector + Realtime)
    supabase_url: Optional[str] = None
    supabase_key: Optional[str] = None
    supabase_service_role_key: Optional[str] = None

    # Storage Paths
    workspace_root: Path = Path(__file__).resolve().parent.parent
    lancedb_path: Path = Path(".lancedb")
    policies_dir: Path = Path("policies")
    audit_output_path: Path = Path("dashboard/assets/latest_audit.json")

    # GitHub Actions Telemetry
    github_token: Optional[str] = None
    github_repository: Optional[str] = None
    github_event_path: Optional[str] = None
    github_ref: Optional[str] = None
    github_sha: Optional[str] = None

    # Offline / Testing Mode: Automatically activates fallback mocks when Ollama/Supabase is unreachable
    allow_offline_fallback: bool = True

    def get_absolute_path(self, path: Path) -> Path:
        """Resolve a path relative to workspace_root if it's not already absolute."""
        if path.is_absolute():
            return path
        return self.workspace_root / path


settings = Settings()
