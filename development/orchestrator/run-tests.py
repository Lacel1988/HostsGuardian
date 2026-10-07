"""Run stdlib tests from either a checkout root or the tooling directory."""
from pathlib import Path
import sys
import os
import unittest
root = Path(__file__).resolve().parent
sys.path.insert(0, str(root))
os.chdir(root)
suite = unittest.defaultTestLoader.discover(str(root/'tests'))
raise SystemExit(not unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful())
