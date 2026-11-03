from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlsplit
from uuid import UUID

from traust_core.v1.errors import TraustError, ValidationError
from traust_core.v1.models.detection_quality import TruePositive
from traust_core.v1.models.rule_calibration import (
    CalibrationCheckout,
    CalibrationReviewSample,
    CalibrationSkip,
    CalibrationStatus,
    PackCalibrationRun,
    RuleCalibrationRequest,
)
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, LocalRepoUrl
from traust_core.v1.providers.sources import CheckoutRequest, Checkouts
from traust_core.v1.providers.tools.rule_calibration import OpengrepCalibration
from traust_core.v1.services.findings.identity import canon_path
from traust_core.v1.services.portfolio import Inventory


def scan_pack(
    scanner: OpengrepCalibration,
    checkouts: Checkouts,
    inventory: Inventory,
    request: RuleCalibrationRequest,
    corpus: Sequence[TruePositive],
) -> PackCalibrationRun:
    with scanner.prepare(request) as prepared:
        if request.fixtures:
            fixture = scanner.fixtures(prepared, request)
            return PackCalibrationRun(
                pack=prepared.pack,
                status=(
                    CalibrationStatus.COMPLETED
                    if fixture.scan.complete
                    else CalibrationStatus.FAILED
                ),
                fixture=fixture,
            )
        if not corpus:
            raise ValidationError("live calibration needs recorded confirmed true positives")
        by_ref: dict[UUID, list[TruePositive]] = {}
        skipped: list[CalibrationSkip] = []
        for tp in corpus:
            if tp.repository_ref_id is None:
                skipped.append(
                    CalibrationSkip(finding_id=tp.finding_id, reason="no recorded corpus commit")
                )
            else:
                by_ref.setdefault(tp.repository_ref_id, []).append(tp)
        rows: list[CalibrationCheckout] = []
        samples: list[CalibrationReviewSample] = []
        for index, (repository_ref_id, tps) in enumerate(by_ref.items()):
            if request.limit is not None and index >= request.limit:
                skipped.extend(
                    CalibrationSkip(finding_id=tp.finding_id, reason="calibration commit limit")
                    for tp in tps
                )
                continue
            subject = inventory.subject(repository_ref_id)
            if any(tp.repository_id != subject.repository_id for tp in tps):
                raise ValidationError(f"corpus commit {repository_ref_id} belongs to another repo")
            workspace = None
            try:
                url = subject.repository_url
                origin = (
                    HttpsRepoUrl.parse(url, [urlsplit(url).hostname or ""])
                    if url.startswith("https://")
                    else LocalRepoUrl.parse(url)
                )
                workspace = checkouts.checkout(
                    CheckoutRequest(repo=origin, ref=GitSha.parse(subject.sha))
                ).data
                if workspace.sha != GitSha.parse(subject.sha) or workspace.repo != origin:
                    raise ValidationError(f"checkout returned the wrong corpus commit for {url}")
                scan = scanner.scan(prepared, workspace.path, request)
                rows.append(
                    CalibrationCheckout(
                        subject=subject,
                        scan=scan,
                        reason=None if scan.complete else "scanner incomplete; see scan counts",
                    )
                )
                paths = {canon_path(p) for tp in tps for p in tp.paths}
                samples.extend(
                    CalibrationReviewSample(
                        subject=subject, hit=hit, rediscovered=canon_path(hit.path) in paths
                    )
                    for hit in scan.hits
                )
            except (TraustError, OSError) as e:
                rows.append(CalibrationCheckout(subject=subject, reason=str(e)))
            finally:
                if workspace is not None:
                    checkouts.release(workspace)
        complete = sum(row.scan is not None and row.scan.complete for row in rows)
        status = (
            CalibrationStatus.FAILED
            if not complete
            else CalibrationStatus.DEGRADED
            if complete != len(rows) or skipped
            else CalibrationStatus.COMPLETED
        )
        samples.sort(key=lambda s: (s.rediscovered, str(s.subject.repository_ref_id), s.hit.path))
        return PackCalibrationRun(
            pack=prepared.pack,
            status=status,
            checkouts=tuple(rows),
            skipped=tuple(skipped),
            review_sample=tuple(samples[:100]),
        )
