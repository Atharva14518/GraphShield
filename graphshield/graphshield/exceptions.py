"""
GraphShield custom exception hierarchy.

All exceptions inherit from GraphShieldError to allow broad
catching when needed, while remaining individually catchable
for fine-grained error handling.
"""

from __future__ import annotations
from typing import Optional


class GraphShieldError(Exception):
    """
    Base exception for all GraphShield errors.

    Args:
        message: Human-readable description of the error.
        cause: Optional underlying exception that triggered this error.
    """

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        self.message = message
        self.cause = cause
        super().__init__(message)

    def __str__(self) -> str:
        if self.cause is not None:
            return f"{self.message} (caused by: {type(self.cause).__name__}: {self.cause})"
        return self.message

    def __repr__(self) -> str:
        return f"{type(self).__name__}(message={self.message!r}, cause={self.cause!r})"


class CVEFetchError(GraphShieldError):
    """
    Raised when downloading or parsing NVD CVE feeds fails.

    Args:
        message: Description of the fetch failure, including URL and attempt count.
        cause: Underlying network or I/O exception.
    """

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        super().__init__(f"CVE fetch failed: {message}", cause)


class ManifestParseError(GraphShieldError):
    """
    Raised when a package manifest file cannot be parsed.

    Args:
        message: Description of what failed during parsing.
        cause: Underlying parse or I/O exception (e.g. json.JSONDecodeError).
    """

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        super().__init__(f"Manifest parse error: {message}", cause)


class BloomFilterError(GraphShieldError):
    """
    Raised when Bloom Filter construction, serialization, or lookup fails.

    Args:
        message: Description of the Bloom Filter failure.
        cause: Underlying I/O or parameter validation exception.
    """

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        super().__init__(f"Bloom filter error: {message}", cause)


class ScanError(GraphShieldError):
    """
    Raised when a vulnerability scan cannot proceed or complete.

    Args:
        message: Description of what prevented the scan from completing.
        cause: Underlying exception (e.g., missing manifest, DB error).
    """

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        super().__init__(f"Scan error: {message}", cause)


class AgentError(GraphShieldError):
    """
    Raised when an LLM agent call fails or returns unparseable output.

    Args:
        message: Description of the agent failure (API error, JSON parse failure, etc.).
        cause: Underlying exception from the Groq SDK or JSON parser.
    """

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        super().__init__(f"Agent error: {message}", cause)
