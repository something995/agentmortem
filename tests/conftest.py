from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

MALICIOUS = ROOT / "examples" / "transcripts" / "malicious_session.jsonl"
BENIGN = ROOT / "examples" / "transcripts" / "benign_session.jsonl"
BAD_CONFIG = ROOT / "examples" / "configs" / "bad-agent"
GOOD_CONFIG = ROOT / "examples" / "configs" / "good-agent"
