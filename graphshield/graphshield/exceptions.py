
from __future__ import annotations
from typing import Optional

class GraphShieldError(Exception):

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

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        super().__init__(f"CVE fetch failed: {message}", cause)

class ManifestParseError(GraphShieldError):

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        super().__init__(f"Manifest parse error: {message}", cause)

class BloomFilterError(GraphShieldError):

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        super().__init__(f"Bloom filter error: {message}", cause)

class ScanError(GraphShieldError):

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        super().__init__(f"Scan error: {message}", cause)

class AgentError(GraphShieldError):

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        super().__init__(f"Agent error: {message}", cause)
