from dataclasses import dataclass
from enum import StrEnum


class TraustError(Exception):
    pass


class ValidationError(TraustError, ValueError):
    pass


class NotFoundError(TraustError, LookupError):
    pass


class RepositoryError(TraustError):
    def __init__(self, *args: object, operation: str | None = None) -> None:
        super().__init__(*args)
        self.operation = operation


class ConflictError(RepositoryError):
    pass


class AuthenticationError(TraustError):
    """The caller could not be identified (no, bad or refused credential)."""


class ForbiddenError(TraustError, PermissionError):
    """The caller is known but may not do this (a gate refused it)."""


class IntegrityError(TraustError):
    pass


class ConfigError(TraustError):
    pass


class PreflightError(ConfigError):
    """A deployment lacks something an enabled pack asset requires; the message lists every
    gap with its fix."""


class DeploymentConfigMissing(ConfigError, FileNotFoundError):
    """A required deployment config file, or the config home itself, is missing."""


class ServiceError(TraustError):
    def __init__(
        self,
        message: str,
        status: int | None = None,
        *,
        operation: str | None = None,
        target_hash: str | None = None,
        endpoint_unreachable: bool = False,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.operation = operation
        self.target_hash = target_hash
        # True only when the transport positively established the endpoint is not
        # there - name resolution failed (NXDOMAIN), the connection was refused, or
        # TLS failed its handshake. A timeout or a reset said nothing (the endpoint
        # might be there), so it is never this: the gone-class distinction the
        # repository's unreachable disposition counts on (foundry plan
        # repo-unreachable: only the gone-class counts, never the transient classes).
        self.endpoint_unreachable = endpoint_unreachable


class ScannerFailure(StrEnum):
    TIMEOUT = "scan_timeout"
    EXIT = "opengrep_failed"
    OUTPUT = "invalid_output"


class ScannerError(ServiceError):
    """A scanner process failed without exposing its private input or output."""

    def __init__(
        self,
        message: str,
        *,
        reason: ScannerFailure,
        exit_code: int | None = None,
        timeout_seconds: int | None = None,
    ) -> None:
        super().__init__(message, status=exit_code, operation="opengrep.scan")
        self.reason = reason
        self.exit_code = exit_code
        self.timeout_seconds = timeout_seconds


@dataclass(frozen=True, slots=True)
class Issue:
    path: str
    message: str


class DocumentError(ValidationError):
    def __init__(self, document: str, issues: list[Issue]) -> None:
        first = issues[0]
        super().__init__(
            f"{document}: {len(issues)} issue(s); first: {first.path}: {first.message}"
        )
        self.document = document
        self.issues = issues


class ViewContractError(DocumentError):
    """A view Core built fails its own contract: Core's fault (500, logged), never the caller's
    request; it stays a DocumentError, so a caller catching that still catches it."""


class RemovedSecretError(DocumentError):
    """A patch carries high-confidence secrets only outside its added lines."""


class UnresolvedTargetError(ValidationError):
    """A component PURL target could not be deterministically verified against the pinned tree."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"unresolved target ({reason}): {detail}")
        self.reason = reason
        self.detail = detail
