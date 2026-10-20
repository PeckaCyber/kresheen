import pytest

from kresheen.engine.dfd.rename import rename_element_key


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("process:Web", "process:Storefront"),
        ("data_store:Web", None),  # different type: a different component
        ("process:Webby", None),
        ("flow:Web->DB", "flow:Storefront->DB"),
        ("flow:DB->Web", "flow:DB->Storefront"),
        ("flow:Web->Web", "flow:Storefront->Storefront"),
        ("flow:DB->Cache", None),
    ],
)
def test_rename_element_key(key, expected):
    assert rename_element_key(key, "process", "Web", "Storefront") == expected


def test_rename_element_key_handles_names_containing_an_arrow():
    assert rename_element_key("flow:a->b->DB", "process", "a->b", "X") == "flow:X->DB"
