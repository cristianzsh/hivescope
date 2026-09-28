#!/usr/bin/env python3
"""
HiveScope launcher

Run the GUI:
    python3 HiveScope.py

Headless examples:
    python3 HiveScope.py --folder /path/to/collection --html report.html
    python3 HiveScope.py --system SYSTEM --software SOFTWARE --sam SAM --text out.txt
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hivescope.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
