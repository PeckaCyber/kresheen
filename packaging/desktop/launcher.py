"""Entry point of the desktop build: `kresheen desktop` when started with no arguments (a double-click or a menu
entry), the full `kresheen` CLI otherwise (for example `kresheen create-user`)."""

import multiprocessing
import sys

from kresheen.cli.main import cli

if __name__ == "__main__":
    multiprocessing.freeze_support()
    if len(sys.argv) == 1:
        sys.argv.append("desktop")
    cli()
