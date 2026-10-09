"""Backward-compatible application entry point. Run with ``python vocab_app.py``."""

import os

from run import app


if __name__ == "__main__":
    port = int(os.environ.get("VOCAB_PORT", "5050"))
    app.run(host="127.0.0.1", port=port, debug=False)