from dataclasses import dataclass


class TraustError(Exception):
    pass


class ValidationError(TraustError, ValueError):
    pass


class NotFoundError(TraustError, LookupError):
    pass


class RepositoryError(TraustError):
    def __init__(self, message: str, *, operation: str | None = None) -> None:
        super().__init__(message)
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
    ) -> None:
        super().__init__(message)
        self.status = status
        self.operation = operation
        self.target_hash = target_hash


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
