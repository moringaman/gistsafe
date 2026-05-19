"""Utility functions for GistSafe."""

from .constants import ENVIRONMENT_SHORT_FORMS


def normalize_environment(env: str) -> str:
    """Normalize environment names to handle common variations.

    Converts short forms (dev, prod, stage, qa) to their full equivalents
    and lowercases everything for consistent matching.
    """
    env_lower = env.lower()
    return ENVIRONMENT_SHORT_FORMS.get(env_lower, env_lower)
