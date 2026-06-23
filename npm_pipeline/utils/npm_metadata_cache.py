"""Persistent, multi-process safe cache for :class:`NpmPkgMetadata`.

Design notes
------------

The cache stores **one JSON file per npm package** under ``cache_dir``. The
filename is a SHA-256 hash of the package name so we never have to worry about
filesystem-illegal characters (``@scope/name``, etc.).

Concurrency model:

* **Atomic writes** — payloads are written to a temp file in the same
  directory and then ``os.replace``-d into place. ``os.replace`` is atomic on
  POSIX and on Windows (within the same volume), so readers never observe a
  partially written file.
* **Atomic reads** — opening + parsing a JSON file picks up either the old
  contents or the new contents, never a mix.
* **De-duplicated fetches** — :meth:`get_or_fetch` takes an exclusive
  ``fcntl`` byte-range lock before invoking the upstream fetcher, with a
  double-check pattern.



The cache is intentionally schema-tolerant: ``NpmPkgMetadata`` objects are
serialized into a plain ``dict`` of their public attributes, and missing keys
on read are treated as ``None``. Old payloads written by a previous version
remain readable.
"""

import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from typing import Callable, Iterator

import yaml
from loguru import logger

from npm_pipeline.classes.npm_pkg_metadata import NpmPkgMetadata

try:
    import fcntl  # type: ignore[attr-defined]

    _HAS_FCNTL = True
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None  # type: ignore[assignment]
    _HAS_FCNTL = False


_CACHE_FORMAT_VERSION = 1

# Single shared lock file for the whole cache directory. Per-package isolation
# is realised through disjoint byte-range locks on this one file.
_LOCK_FILE_NAME = "__locks__.lock"

# Size of the byte-offset space packages are hashed into. Large enough that
# collisions (and thus false contention between unrelated packages) are
# negligible, while staying well within a 64-bit off_t.
_LOCK_SPACE = 1 << 31


def _serialize(meta: NpmPkgMetadata) -> dict:
    """Convert an :class:`NpmPkgMetadata` instance to a JSON-safe dict."""
    return {
        "package_name": meta.package_name,
        "package_version_list": meta.package_version_list,
        "package_description": meta.package_description,
        "package_keywords": meta.package_keywords,
        "package_repository": meta.package_repository,
        "package_changelog": meta.package_changelog,
        "package_weekly_downloads": meta.package_weekly_downloads,
        "package_readme_text": meta.package_readme_text,
        "package_dependents_count": meta.package_dependents_count,
        "package_declaration_files": meta.package_declaration_files,
    }


def _deserialize(data: dict) -> NpmPkgMetadata:
    """Reconstruct an :class:`NpmPkgMetadata` from a previously stored dict."""
    return NpmPkgMetadata(
        package_name=data.get("package_name"),
        package_version_list=data.get("package_version_list"),
        package_description=data.get("package_description"),
        package_maintainers=None,
        package_contributors=None,
        package_keywords=data.get("package_keywords"),
        package_repository=data.get("package_repository"),
        package_changelog=data.get("package_changelog"),
        package_weekly_downloads=data.get("package_weekly_downloads"),
        package_readme_text=data.get("package_readme_text"),
        package_dependents_count=data.get("package_dependents_count"),
        package_declaration_files=data.get("package_declaration_files"),
    )


class NpmMetadataCache:
    """Persistent, multi-process safe metadata cache.

    Parameters
    ----------
    cache_dir:
        Directory used to store the JSON payloads. Will be created if missing.
    """

    _CONFIG_PATH = "./config.yaml"
    _CONFIG_KEY = "npm_metadata_cache"
    _DEFAULT_CACHE_DIR_NAME = "npm_metadata"

    def __init__(self, cache_dir: str):
        self._cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    @classmethod
    def default_cache_dir(cls) -> str:
        """Return the default cache directory under the tool root."""
        tool_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)
        )
        return os.path.join(tool_dir, cls._DEFAULT_CACHE_DIR_NAME)

    @classmethod
    def from_config(cls, config_path: str | None = None) -> "NpmMetadataCache":
        """Build a cache using the ``npm_metadata_cache`` section of config.yaml.

        Expected schema::

            npm_metadata_cache:
              dir: "/abs/path/to/npm_metadata"   # optional
        """
        path = config_path or cls._CONFIG_PATH
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

        section = config.get(cls._CONFIG_KEY) or {}
        cache_dir = section.get("dir") or cls.default_cache_dir()
        return cls(cache_dir=os.path.abspath(os.path.expanduser(cache_dir)))

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _key(self, package_name: str) -> str:
        return hashlib.sha256(package_name.encode("utf-8")).hexdigest()

    def _path_for(self, package_name: str) -> str:
        return os.path.join(self._cache_dir, f"{self._key(package_name)}.json")

    def _lock_file_path(self) -> str:
        return os.path.join(self._cache_dir, _LOCK_FILE_NAME)

    def _lock_offset(self, package_name: str) -> int:
        """Map *package_name* to a stable byte offset in the shared lock file."""
        digest = hashlib.sha256(package_name.encode("utf-8")).digest()
        return int.from_bytes(digest[:8], "big") % _LOCK_SPACE

    # ------------------------------------------------------------------
    # Locking
    # ------------------------------------------------------------------

    @contextmanager
    def _exclusive_lock(self, package_name: str) -> Iterator[None]:
        """Take an inter-process exclusive lock for *package_name*.

        Uses a byte-range lock (:func:`fcntl.lockf`) on a single shared lock
        file so the cache directory never accumulates more than one ``.lock``
        file regardless of how many packages are seen. The locked region is a
        single byte at an offset derived from the package name, so distinct
        packages lock disjoint ranges and proceed concurrently.

        Falls back to a no-op on platforms without :mod:`fcntl` (Windows). On
        such platforms duplicate fetches are still possible but writes remain
        atomic, so correctness is preserved.
        """
        if not _HAS_FCNTL:
            yield
            return

        offset = self._lock_offset(package_name)
        # Open read/write (create if absent); lockf requires a writable fd for
        # an exclusive lock. Locking a range beyond EOF on an empty file is
        # valid per POSIX, so we never need to grow the file.
        fd = os.open(self._lock_file_path(), os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX, 1, offset, os.SEEK_SET)
            try:
                yield
            finally:
                fcntl.lockf(fd, fcntl.LOCK_UN, 1, offset, os.SEEK_SET)
        finally:
            os.close(fd)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, package_name: str) -> tuple[bool, NpmPkgMetadata | None]:
        """Look up *package_name* in the cache.

        Returns a ``(hit, value)`` tuple:

        * ``hit=True, value=NpmPkgMetadata`` — cached metadata available.
        * ``hit=True, value=None`` — a previous fetch attempt determined that
          the package has no usable metadata; no need to retry.
        * ``hit=False, value=None`` — cache miss.
        """
        path = self._path_for(package_name)
        if not os.path.exists(path):
            return False, None

        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"[Cache] Corrupt cache file for {package_name} ({path}): {e}")
            return False, None

        data = payload.get("data")
        if data is None:
            return True, None

        try:
            return True, _deserialize(data)
        except Exception as e:
            logger.warning(f"[Cache] Failed to deserialize cache for {package_name}: {e}")
            return False, None

    def set(self, package_name: str, metadata: NpmPkgMetadata | None) -> None:
        """Atomically persist *metadata* (or a tombstone for ``None``)."""
        path = self._path_for(package_name)
        payload = {
            "version": _CACHE_FORMAT_VERSION,
            "package_name": package_name,
            "data": _serialize(metadata) if metadata is not None else None,
        }

        tmp_fd, tmp_path = tempfile.mkstemp(dir=self._cache_dir, prefix=".tmp_", suffix=".json")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
        except Exception as e:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass
            logger.warning(f"[Cache] Failed to write cache for {package_name}: {e}")

    def get_or_fetch(
        self,
        package_name: str,
        fetcher: Callable[[str], NpmPkgMetadata | None],
    ) -> NpmPkgMetadata | None:
        """Return cached metadata, or invoke *fetcher* under a per-package lock.

        Implements the standard double-checked locking pattern so that
        concurrent processes asking for the same package only run *fetcher*
        once.
        """
        hit, value = self.get(package_name)
        if hit:
            logger.debug(f"[Cache] Hit (fast path) for {package_name}")
            return value

        with self._exclusive_lock(package_name):
            hit, value = self.get(package_name)
            if hit:
                logger.debug(f"[Cache] Hit (post-lock) for {package_name}")
                return value

            logger.info(f"[Cache] Miss for {package_name}; invoking fetcher")
            try:
                value = fetcher(package_name)
            except Exception as e:
                logger.warning(f"[Cache] Fetcher raised for {package_name}: {e}")
                value = None

            self.set(package_name, value)
            return value

    def invalidate(self, package_name: str) -> None:
        """Remove a single entry from the cache (best-effort)."""
        path = self._path_for(package_name)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.warning(f"[Cache] Failed to invalidate {package_name}: {e}")

    # ------------------------------------------------------------------
    # Derived-results helpers
    # ------------------------------------------------------------------
    #
    # The ``derived`` section stores LLM-computed results so we never pay for
    # the same prompt twice. Layout::
    #
    #     {
    #       ...,
    #       "derived": {
    #         "is_trustworthy": true,
    #         "module_behavior": "...",
    #         "api_behavior": {"get": "...", "post": null, ...}
    #       }
    #     }
    #
    # **Key presence indicates a cache hit, even when the value is ``None``.**
    # That lets us tombstone "the LLM said unknown" so we don't keep retrying.

    def _read_payload(self, package_name: str) -> dict | None:
        path = self._path_for(package_name)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"[Cache] Corrupt cache file for {package_name}: {e}")
            return None

    def _write_payload(self, package_name: str, payload: dict) -> None:
        path = self._path_for(package_name)
        tmp_fd, tmp_path = tempfile.mkstemp(dir=self._cache_dir, prefix=".tmp_", suffix=".json")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
        except Exception as e:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass
            logger.warning(f"[Cache] Failed to write cache for {package_name}: {e}")

    def get_derived(self, package_name: str) -> dict:
        """Return the ``derived`` section of *package_name* (empty if absent)."""
        payload = self._read_payload(package_name)
        if not payload:
            return {}
        derived = payload.get("derived")
        return dict(derived) if isinstance(derived, dict) else {}

    def update_derived(self, package_name: str, patch: dict) -> None:
        """Merge *patch* into ``derived`` under the per-package lock.

        ``api_behavior`` is merged shallowly (per-method override), every other
        key is overwritten outright. The whole operation is read-modify-write
        guarded by :meth:`_exclusive_lock`, so concurrent processes that update
        different methods of the same package will not lose each other's
        writes.

        If the base metadata file does not exist yet (e.g. a previous fetch
        returned ``None``), the call is a no-op — derived results don't make
        sense without raw metadata.
        """
        if not patch:
            return

        with self._exclusive_lock(package_name):
            payload = self._read_payload(package_name)
            if payload is None:
                logger.debug(
                    f"[Cache] Skipping derived update for {package_name}: no base payload on disk."
                )
                return

            derived = payload.get("derived")
            if not isinstance(derived, dict):
                derived = {}

            for key, value in patch.items():
                if key == "api_behavior" and isinstance(value, dict):
                    existing = derived.get("api_behavior")
                    merged = dict(existing) if isinstance(existing, dict) else {}
                    merged.update(value)
                    derived["api_behavior"] = merged
                else:
                    derived[key] = value

            payload["derived"] = derived
            self._write_payload(package_name, payload)
