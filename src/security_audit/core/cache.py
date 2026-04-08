"""Cache module for security audit checks."""

import time
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

T = TypeVar("T")


class CheckCache:
    """In-memory cache for security check results with TTL support."""

    def __init__(self, ttl: int = 3600) -> None:
        """Initialize the cache.

        Args:
            ttl: Time-to-live in seconds (default 3600).
        """
        self._cache: dict[str, tuple[Any, float]] = {}
        self._ttl = ttl
        self._enabled = False

    @property
    def ttl(self) -> int:
        """Get the TTL in seconds."""
        return self._ttl

    @ttl.setter
    def ttl(self, value: int) -> None:
        """Set the TTL in seconds."""
        self._ttl = value

    @property
    def enabled(self) -> bool:
        """Check if cache is enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Set cache enabled state."""
        self._enabled = value

    def get(self, key: str) -> Any | None:
        """Get a value from the cache.

        Args:
            key: The cache key.

        Returns:
            The cached value if exists and not expired, None otherwise.
        """
        if not self._enabled:
            return None
        entry = self._cache.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.time() > expires_at:
            del self._cache[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        """Set a value in the cache.

        Args:
            key: The cache key.
            value: The value to cache.
        """
        if not self._enabled:
            return
        self._cache[key] = (value, time.time() + self._ttl)

    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()


_global_cache: CheckCache | None = None


def get_cache() -> CheckCache | None:
    """Get the global cache instance."""
    return _global_cache


def init_cache(enabled: bool = False, ttl: int = 3600) -> CheckCache:
    """Initialize the global cache.

    Args:
        enabled: Whether caching is enabled.
        ttl: Time-to-live in seconds.

    Returns:
        The initialized cache.
    """
    global _global_cache
    _global_cache = CheckCache(ttl=ttl)
    if enabled:
        _global_cache.enabled = True
    return _global_cache


def clear_cache() -> None:
    """Clear the global cache."""
    global _global_cache
    if _global_cache is not None:
        _global_cache.clear()


def cached_check(
    check_name: str,
) -> Callable[[Callable[..., list[T]]], Callable[..., list[T]]]:
    """Decorator to cache check function results.

    Args:
        check_name: Unique name for the check (used as cache key).

    Returns:
        A decorator function.
    """

    def decorator(func: Callable[..., list[T]]) -> Callable[..., list[T]]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> list[T]:
            cache = get_cache()
            if cache is None or not cache.enabled:
                return func(*args, **kwargs)
            cached = cache.get(check_name)
            if cached is not None:
                return cached  # type: ignore[no-any-return]
            result = func(*args, **kwargs)
            cache.set(check_name, result)
            return result

        return wrapper

    return decorator
