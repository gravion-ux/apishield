#!/usr/bin/env python3
"""Run the APIShield attack-replay demo (same as `apishield demo`)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from apishield.demo import main

if __name__ == "__main__":
    main()
