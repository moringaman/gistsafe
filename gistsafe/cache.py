"""Thread-safe file-based cache for GistSafe project metadata.

Stores project names, environments, gist IDs, and URLs locally.
Never stores secrets or sensitive values.
"""

import json
import os
import threading
import time

from .constants import CACHE_DIR, CACHE_FILENAME, CACHE_TTL_SECONDS
from .display import console


class CacheManager:
    """Thread-safe JSON file cache for GistSafe project index."""

    def __init__(self) -> None:
        self.cache_dir = os.path.expanduser(CACHE_DIR)
        self.cache_file = os.path.join(self.cache_dir, CACHE_FILENAME)
        self._lock = threading.RLock()
        self._projects: dict[str, dict] = {}
        self._last_update: float = 0

    def __bool__(self) -> bool:
        return bool(self._projects)

    def load(self) -> None:
        """Load cache from disk. Creates a fresh cache if none exists or on corruption."""
        try:
            if os.path.exists(self.cache_file):
                with self._lock:
                    with open(self.cache_file) as f:
                        data = json.load(f)
                    self._projects = data.get("projects", {})
                    self._last_update = data.get("last_update", 0)
                    console.print(f"[green]Loaded {len(self._projects)} projects from cache")
            else:
                console.print("[yellow]No cache file found")
                self._projects = {}
                self._last_update = 0
        except (json.JSONDecodeError, OSError) as e:
            console.print(f"[red]Error loading cache: {e}")
            self._projects = {}
            self._last_update = 0

    def save(self) -> bool:
        """Save cache to disk. Returns True on success."""
        try:
            os.makedirs(self.cache_dir, mode=0o755, exist_ok=True)

            if not os.access(self.cache_dir, os.W_OK):
                console.print(f"[red]Cache directory not writable: {self.cache_dir}")
                return False

            with self._lock:
                data = {
                    "projects": self._projects,
                    "last_update": time.time(),
                }
                with open(self.cache_file, "w") as f:
                    json.dump(data, f, indent=2)

            console.print("[green]Cache saved successfully")
            return True
        except (OSError, PermissionError) as e:
            console.print(f"[red]Error saving cache: {e}")
            return False

    def needs_refresh(self) -> bool:
        """Check if cache is stale (older than TTL) or empty."""
        if not self._projects:
            return True
        return (time.time() - self._last_update) > CACHE_TTL_SECONDS

    def get(self, project: str, environment: str) -> dict | None:
        """Get cached gist metadata for a project/environment pair.

        Performs case-insensitive environment matching.
        """
        with self._lock:
            if project not in self._projects:
                return None
            env_lower = environment.lower()
            for env, data in self._projects[project].get("environments", {}).items():
                if env.lower() == env_lower:
                    return data
        return None

    def update(
        self,
        project: str,
        environment: str,
        gist_id: str,
        filename: str,
        gist_url: str,
    ) -> None:
        """Update cache entry for a project/environment and persist to disk."""
        with self._lock:
            if project not in self._projects:
                self._projects[project] = {
                    "environments": {},
                    "gist_url": gist_url,
                }
            self._projects[project]["environments"][environment] = {
                "filename": filename,
                "gist_id": gist_id,
            }
        self.save()

    def get_all(self) -> dict[str, dict]:
        """Return a copy of all cached projects."""
        with self._lock:
            return dict(self._projects)

    def replace_all(self, projects: dict[str, dict]) -> None:
        """Atomically replace the entire cache with new project data."""
        with self._lock:
            self._projects = projects
            self._last_update = time.time()
        self.save()
