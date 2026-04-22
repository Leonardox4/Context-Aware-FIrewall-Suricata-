"""
Simple logging: print to stdout with optional prefix. No logging.config.
"""

import sys


def log(msg, level="INFO"):
    print(f"[{level}] {msg}", file=sys.stderr, flush=True)
