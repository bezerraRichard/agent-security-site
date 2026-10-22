"""Streamlit console. ``agent-security-console`` starts it on localhost only, without usage statistics."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from agent_security.envfile import load_env_file

APP = Path(__file__).with_name("app.py")
# Both palettes are configured, so the console follows the system setting and the viewer can switch between light
# and dark in the ⋮ menu.
THEMES = {
    "light": {
        "primaryColor": "#009F98",
        "backgroundColor": "#FFFFFF",
        "secondaryBackgroundColor": "#EDF4F5",
        "textColor": "#273C4E",
    },
    "dark": {
        "primaryColor": "#00B9B2",
        "backgroundColor": "#0F1C27",
        "secondaryBackgroundColor": "#1B2C3A",
        "textColor": "#E4EDEF",
    },
}


def main(argv: Sequence[str] | None = None) -> int:
    load_env_file()  # Settings from ./.env; variables already set in the shell win.
    parser = argparse.ArgumentParser(prog="agent-security-console", description="HTTP Security console (Streamlit).")
    parser.add_argument(
        "--output-dir",
        default=os.environ.get("AGENT_SECURITY_REPORTS_DIR") or "reports",
        help="Folder where reports are written and read",
    )
    parser.add_argument("--port", type=int, default=int(os.environ.get("AGENT_SECURITY_CONSOLE_PORT") or 8501))
    args = parser.parse_args(argv)
    try:
        from streamlit.web import cli as streamlit_cli
    except ImportError:
        print('Streamlit is not installed. Run: pip install -e ".[console]"', file=sys.stderr)
        return 2
    from agent_security.console.state import REPORTS_ENV

    os.environ[REPORTS_ENV] = str(Path(args.output_dir).resolve())
    sys.argv = [
        "streamlit",
        "run",
        str(APP),
        "--server.address=localhost",  # Never expose the console on the network.
        f"--server.port={args.port}",
        "--browser.gatherUsageStats=false",
        "--client.toolbarMode=viewer",  # Keeps the ⋮ menu (theme choice) without developer options.
        *(f"--theme.{mode}.{key}={value}" for mode, palette in THEMES.items() for key, value in palette.items()),
    ]
    streamlit_cli.main()
    return 0
