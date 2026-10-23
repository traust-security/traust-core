from dataclasses import FrozenInstanceError

import pydantic
import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.onboarding import OnboardingRequest
from traust_core.v1.models.values import ProductSlug


@pytest.mark.parametrize("raw", ["a", "9", "OpenShift", "platform-4.16_x", "A._-"])
def test_product_slug_preserves_accepted_text(raw: str) -> None:
    slug = ProductSlug.parse(raw)
    assert str(slug) == raw
    assert slug == ProductSlug(raw)
    assert len({slug, ProductSlug(raw)}) == 1


@pytest.mark.parametrize(
    "raw",
    [
        "",
        " ",
        "a b",
        " a",
        "a ",
        "a\n",
        "a\t",
        "a\x00",
        ".hidden",
        "-option",
        "_name",
        "a/b",
        "a\\b",
        "a?b",
        "ümlaut",
        "\uff21",
        None,
        1,
        True,
        b"product",
        {"value": "product"},
    ],
)
@pytest.mark.parametrize("parse", [False, True], ids=["constructor", "parse"])
def test_product_slug_rejects_invalid_text_at_construction(raw: object, parse: bool) -> None:
    with pytest.raises(ValidationError, match=r"product\.slug"):
        (ProductSlug.parse if parse else ProductSlug)(raw)  # type: ignore[arg-type]


def test_product_slug_is_immutable_and_case_sensitive() -> None:
    slug = ProductSlug("Example")
    with pytest.raises(FrozenInstanceError):
        slug.value = "changed"  # type: ignore[misc]
    assert slug != ProductSlug("example")


def test_onboarding_parses_slug_and_preserves_the_string_wire_format() -> None:
    request = OnboardingRequest.model_validate_json('{"product":"OpenShift-4.16"}')
    assert request.product == ProductSlug("OpenShift-4.16")
    assert request.model_dump()["product"] == "OpenShift-4.16"
    assert OnboardingRequest.model_validate_json(request.model_dump_json()) == request
    assert OnboardingRequest(product=request.product) == request
    assert OnboardingRequest.model_validate(request.model_dump()) == request


@pytest.mark.parametrize("raw", ["", "bad/name", " product ", None, 123, {"value": "product"}])
def test_onboarding_rejects_invalid_slug_input(raw: object) -> None:
    with pytest.raises(pydantic.ValidationError, match="product"):
        OnboardingRequest.model_validate({"product": raw})


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_onboarding_schema_keeps_product_as_text(mode: str) -> None:
    schema = OnboardingRequest.model_json_schema(mode=mode)  # type: ignore[arg-type]
    assert schema["properties"]["product"]["type"] == "string"
