from __future__ import annotations

import argparse
from pathlib import Path

from traust_core.v1.models.insight import InsecurePatterns
from traust_core.v1.rendering import HtmlRenderer, MarkdownRenderer
from traust_core.v1.services.insight import InsecurePatternsView

FIXTURE = Path(__file__).parents[2] / "fixtures" / "insight" / "insecure-patterns.json"


def render_fixture(destination: Path) -> None:
    """Render the explicitly synthetic 52-pattern fixture with production report/render owners."""
    model = InsecurePatterns.model_validate_json(FIXTURE.read_text())
    assert model.as_of is not None
    report = InsecurePatternsView.report(model, model.as_of).model_copy(
        update={"title": "Insecure patterns — synthetic verification fixture"}
    )
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "insecure-patterns.html").write_bytes(HtmlRenderer().render(report))
    (destination / "insecure-patterns.md").write_bytes(MarkdownRenderer().render(report))
    (destination / "insecure-patterns.json").write_text(model.model_dump_json(indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Render synthetic insecure-patterns browser fixture"
    )
    parser.add_argument("destination", type=Path)
    render_fixture(parser.parse_args().destination)
