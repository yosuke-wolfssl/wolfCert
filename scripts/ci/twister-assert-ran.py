#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Assert that named twister suites actually executed and passed.

twister exits 0 when every selected configuration is filtered out or built
only, so a fixture rename or a platform_allow typo turns a gate green without
running anything. Pass the twister.json and the suite names the step exists to
run; this fails when one is missing, skipped, built-only or failed.

    twister-assert-ran.py <twister.json> <suite> [<suite> ...]
"""

import json
import sys


def main(argv):
    if len(argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    report, wanted = argv[1], argv[2:]

    try:
        with open(report) as fh:
            suites = json.load(fh).get("testsuites", [])
    except (OSError, ValueError) as exc:
        print(f"::error::cannot read {report}: {exc}", file=sys.stderr)
        return 1

    # twister names a suite by its path; match on the trailing component.
    seen = {}
    for suite in suites:
        seen[suite.get("name", "").rsplit("/", 1)[-1]] = suite.get("status")

    rc = 0
    for name in wanted:
        status = seen.get(name)
        if status is None:
            print(f"::error::{name} did not run (not in {report})", file=sys.stderr)
            rc = 1
        elif status != "passed":
            print(f"::error::{name} status is '{status}', expected 'passed'",
                  file=sys.stderr)
            rc = 1
        else:
            print(f"{name}: passed")

    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
