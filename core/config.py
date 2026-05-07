"""Configuration loading helpers for OAuth Flask integration."""

from __future__ import annotations

import json
from typing import Any

from .validation import validate_oauth_config


def load_oauth_config(config_file: str) -> dict[str, Any]:
    """Load OAuth config from JSON file and optionally validate it."""
    with open(config_file, encoding="utf-8") as file_obj:
        config = json.load(file_obj)
    return validate_oauth_config(config)
