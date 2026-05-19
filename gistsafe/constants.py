"""Constants used across GistSafe."""

CACHE_TTL_SECONDS = 3600  # 1 hour
CACHE_DIR = "~/.gistsafe"
CACHE_FILENAME = "cache.json"

GISTSAFE_FILE_SUFFIXES = ("_gistsafe.json", "_secrets.json")

PBKDF2_ITERATIONS = 100_000
SALT_LENGTH = 16

MIN_PASSWORD_LENGTH = 8

ENVIRONMENT_SHORT_FORMS: dict[str, str] = {
    "dev": "development",
    "prod": "production",
    "stage": "staging",
    "qa": "testing",
}
