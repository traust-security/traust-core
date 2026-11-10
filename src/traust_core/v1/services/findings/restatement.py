from __future__ import annotations

from traust_core.v1.errors import ForbiddenError
from traust_core.v1.models.findings import Restatement, _approver_identity
from traust_core.v1.models.identity import Principal, Role


class RestatementPolicy:
    """Who may correct the record: a verified person with the restate role, and as many
    independent approvers as the deployment requires (`identity.restatement_approvers`)."""

    def __init__(self, approvers: int = 0) -> None:
        self._approvers = approvers

    def authorize(self, restatement: Restatement, author: Principal) -> frozenset[str]:
        """The approvers to record, if `author` may make this correction."""
        return self.authorize_claim(author, tuple(restatement.independent_approvers(author)))

    normalize = staticmethod(_approver_identity)

    def authorize_claim(self, author: Principal, named: tuple[str, ...]) -> frozenset[str]:
        if not author.is_verified_human():
            raise ForbiddenError(f"{author.ref}: a restatement is a verified human's correction")
        if not author.has_role(Role.RESTATE):
            raise ForbiddenError(f"{author.ref}: restating needs the restate role")
        approvers = frozenset(self.normalize(a) for a in named if self.normalize(a)) - {
            self.normalize(author.identity)
        }
        if len(approvers) < self._approvers:
            raise ForbiddenError(
                f"a restatement needs {self._approvers} approvers besides its author;"
                f" it names {len(approvers)}"
            )
        return approvers
