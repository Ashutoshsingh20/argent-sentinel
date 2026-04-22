from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .simulation import run_phase5_attack_suite


def main() -> None:
    results, metrics = run_phase5_attack_suite()
    payload = {
        "results": [asdict(r) for r in results],
        "metrics": asdict(metrics),
        "targets": metrics.TARGETS,
        "all_tests_passed": all(r.passed for r in results),
    }
    out = Path("outputs/phase5_attack_suite_results.json")
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
