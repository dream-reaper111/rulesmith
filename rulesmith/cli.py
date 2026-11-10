from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import RuleError, scan_directory


def main() -> None:
    parser = argparse.ArgumentParser(prog="rulesmith")
    parser.add_argument("directory", type=Path, help="explicitly authorized local rule directory")
    args = parser.parse_args()
    try:
        result = scan_directory(args.directory)
    except RuleError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
