"""
SENTINEL-X Configuration Loader
Loads sentinel.yaml and thresholds.yaml with environment variable substitution.
"""
import os
import re
import yaml
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("sentinel.config")

# Project root directory
PROJECT_ROOT = Path(__file__).parent.parent


def _substitute_env_vars(value: str) -> str:
    """Replace ${ENV_VAR} patterns with environment variable values."""
    pattern = r'\$\{(\w+)\}'
    def replacer(match):
        var_name = match.group(1)
        return os.environ.get(var_name, match.group(0))
    if isinstance(value, str):
        return re.sub(pattern, replacer, value)
    return value


def _process_config(config: dict) -> dict:
    """Recursively process config dict, substituting env vars."""
    result = {}
    for key, value in config.items():
        if isinstance(value, dict):
            result[key] = _process_config(value)
        elif isinstance(value, str):
            result[key] = _substitute_env_vars(value)
        elif isinstance(value, list):
            result[key] = [
                _substitute_env_vars(v) if isinstance(v, str) else v
                for v in value
            ]
        else:
            result[key] = value
    return result


class SentinelConfig:
    """
    Centralized configuration for SENTINEL-X.
    Loads from YAML files with environment variable substitution.
    """

    def __init__(self, config_dir: Optional[str] = None):
        if config_dir is None:
            config_dir = str(PROJECT_ROOT / "config")
        self.config_dir = Path(config_dir)
        self._config: dict = {}
        self._thresholds: dict = {}
        self._load()

    def _load(self):
        """Load all configuration files."""
        # Load main config
        config_path = self.config_dir / "sentinel.yaml"
        if config_path.exists():
            with open(config_path) as f:
                raw = yaml.safe_load(f) or {}
            self._config = _process_config(raw)
            logger.info(f"Loaded config from {config_path}")
        else:
            logger.warning(f"Config file not found: {config_path}, using defaults")
            self._config = self._defaults()

        # Load thresholds
        thresh_path = self.config_dir / "thresholds.yaml"
        if thresh_path.exists():
            with open(thresh_path) as f:
                self._thresholds = yaml.safe_load(f) or {}
            logger.info(f"Loaded thresholds from {thresh_path}")

    def _defaults(self) -> dict:
        return {
            "system": {
                "hostname": "auto",
                "platform": "auto",
                "poll_interval_seconds": 1,
                "log_level": "INFO",
            },
            "api": {
                "host": "0.0.0.0",
                "port": 8000,
                "secret_key": "change_me_in_production",
            },
            "llm": {
                "provider": "anthropic",
                "model": "claude-haiku-4-5",
                "api_key": "",
                "ollama_url": "http://localhost:11434",
                "ollama_model": "llama3",
                "fallback_enabled": True,
            },
            "storage": {
                "backend": "sqlite",
                "sqlite_path": "data/sentinel.db",
                "event_retention_hours": 24,
            },
            "detection": {
                "rules_dir": "detection/rules",
                "enabled_rules": "all",
            },
            "response": {
                "require_approval": True,
                "audit_log": "data/audit.log",
            },
        }

    # ─── Accessors ──────────────────────────────────

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a config value by dot-separated path.
        Example: config.get('api.port', 8000)
        """
        keys = key_path.split('.')
        value = self._config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
            if value is None:
                return default
        return value

    def get_threshold(self, key_path: str, default: Any = None) -> Any:
        """Get a threshold value by dot-separated path."""
        keys = key_path.split('.')
        value = self._thresholds
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
            if value is None:
                return default
        return value

    @property
    def system(self) -> dict:
        return self._config.get("system", {})

    @property
    def api(self) -> dict:
        return self._config.get("api", {})

    @property
    def llm(self) -> dict:
        return self._config.get("llm", {})

    @property
    def storage_config(self) -> dict:
        return self._config.get("storage", {})

    @property
    def detection(self) -> dict:
        return self._config.get("detection", {})

    @property
    def response(self) -> dict:
        return self._config.get("response", {})

    @property
    def thresholds(self) -> dict:
        return self._thresholds

    @property
    def db_url(self) -> str:
        backend = self.get("storage.backend", "sqlite")
        if backend == "sqlite":
            path = self.get("storage.sqlite_path", "data/sentinel.db")
            return f"sqlite:///{path}"
        elif backend == "postgresql":
            return self.get("storage.postgresql_url", "postgresql://localhost/sentinel")
        return "sqlite:///data/sentinel.db"

    @property
    def poll_interval(self) -> float:
        return float(self.get("system.poll_interval_seconds", 1))

    @property
    def log_level(self) -> str:
        return self.get("system.log_level", "INFO")


# Global singleton
_config_instance: Optional[SentinelConfig] = None


def get_config() -> SentinelConfig:
    """Get the global config singleton."""
    global _config_instance
    if _config_instance is None:
        _config_instance = SentinelConfig()
    return _config_instance


def reload_config():
    """Force reload configuration."""
    global _config_instance
    _config_instance = SentinelConfig()
    return _config_instance
