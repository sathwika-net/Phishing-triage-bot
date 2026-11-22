"""Smoke tests for the Streamlit dashboard, using Streamlit's built-in test runner.

They run app.py headlessly and check it does not crash. They need the
synthetic dataset, so generate it first: python scripts\\generate_samples.py
"""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).parent.parent / "app.py")
DATASET = Path(__file__).parent.parent / "samples" / "dataset"

needs_dataset = pytest.mark.skipif(not DATASET.is_dir(), reason="run scripts/generate_samples.py first")


def run_app():
    return AppTest.from_file(APP, default_timeout=30).run()


def test_app_starts_without_an_email_and_without_errors():
    at = run_app()
    assert not at.exception
    assert any("Choose an email" in info.value for info in at.info)


@needs_dataset
def test_bundled_sample_is_analyzed_and_shows_a_score():
    at = run_app()
    at.sidebar.radio[0].set_value("Use a bundled synthetic sample").run()
    assert not at.exception
    assert at.metric[0].label == "Risk score"


@needs_dataset
def test_malicious_sample_shows_a_high_score():
    at = run_app()
    at.sidebar.radio[0].set_value("Use a bundled synthetic sample").run()
    at.sidebar.selectbox[0].set_value("mal_01_bank_credentials.eml").run()
    assert not at.exception
    assert at.metric[0].value == "100 / 100"


@needs_dataset
def test_every_bundled_sample_renders_without_crashing():
    at = run_app()
    at.sidebar.radio[0].set_value("Use a bundled synthetic sample").run()
    for name in [path.name for path in sorted(DATASET.glob("*.eml"))]:
        at.sidebar.selectbox[0].set_value(name).run()
        assert not at.exception, name
        