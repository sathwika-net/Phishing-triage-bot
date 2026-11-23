"""Dashboard tests for the optional AI explanation tab. All data here is synthetic.

They need the synthetic dataset, so generate it first: python scripts\\generate_samples.py
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).parent.parent / "app.py")
DATASET = Path(__file__).parent.parent / "samples" / "dataset"

needs_dataset = pytest.mark.skipif(not DATASET.is_dir(), reason="run scripts/generate_samples.py first")


def run_app():
    return AppTest.from_file(APP, default_timeout=30).run()


@needs_dataset
def test_explanation_tab_shows_the_rule_based_summary_and_ai_is_off():
    at = run_app()
    at.sidebar.radio[0].set_value("Use a bundled synthetic sample").run()
    at.sidebar.selectbox[0].set_value("mal_01_bank_credentials.eml").run()
    assert not at.exception
    assert any("rated High risk" in text.value for text in at.text)
    assert at.sidebar.checkbox[0].value is False
    assert any("Off." in info.value for info in at.info)


@needs_dataset
def test_ai_explanation_button_uses_the_local_model_and_shows_its_reply(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"message": {"content": "FAKE MODEL SAYS: invoice phishing."}}).encode())

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("LLM_BASE_URL", f"http://127.0.0.1:{server.server_address[1]}")
        at = run_app()
        at.sidebar.radio[0].set_value("Use a bundled synthetic sample").run()
        at.sidebar.selectbox[0].set_value("mal_01_bank_credentials.eml").run()
        at.sidebar.checkbox[0].set_value(True).run()
        next(button for button in at.button if button.label == "Generate AI explanation").click().run()
        assert not at.exception
        assert any("FAKE MODEL SAYS" in text.value for text in at.text)
    finally:
        server.shutdown()
        server.server_close()

        