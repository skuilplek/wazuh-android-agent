#!/usr/bin/env python3
"""
Matches the scenario log from run_scenarios.sh against the manager's alerts.json and reports
which scenarios raised the expected alert.

Usage:
  python3 manager/testing/evaluate.py --scenarios scenario_log.jsonl --alerts alerts.json \
      [--agent AGENT_NAME] [--min-level 5] [--ignore 100216]

A scenario counts as detected when an alert with one of its expected rule ids arrives between
one minute before it was triggered and the end of its window. Other Android alerts of at least
--min-level in the test period are listed as unrelated; some are expected (USB debugging is on
during the test, so rule 100216 is ignored by default).

Exits with status 1 if any scenario was not detected.
"""

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timedelta

SCENARIO_RULES = {
    "developer_options": {"100217"},
    "app_install_adb": {"100232"},
    "app_removed": {"100233"},
    "failed_unlock": {"100260"},
    "unlock_brute_force": {"100261"},
    "adb_shell": {"100241", "100242"},
    "suspicious_domain": {"100291"},
    "agent_offline": {"504"},
}

EARLY_SLACK = timedelta(minutes=1)


def parse_time(value):
    value = value.replace("Z", "+00:00")
    # alerts.json writes offsets as +0200
    value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value)
    return datetime.fromisoformat(value)


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def belongs_to_agent(alert, agent):
    if agent is None:
        return True
    if alert.get("agent", {}).get("name") == agent:
        return True
    # Disconnection alerts come from the manager and name the agent in the log text.
    return agent in alert.get("full_log", "")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenarios", required=True)
    parser.add_argument("--alerts", required=True)
    parser.add_argument("--agent", help="only consider alerts for this agent name")
    parser.add_argument("--min-level", type=int, default=5, help="lowest level listed as an unrelated alert")
    parser.add_argument("--ignore", action="append", default=["100216"], help="rule id to leave out of unrelated alerts")
    args = parser.parse_args()

    scenarios = list(read_jsonl(args.scenarios))
    if not scenarios:
        sys.exit("The scenario log is empty.")
    windows = []
    for s in scenarios:
        start = parse_time(s["triggered_at"])
        windows.append((start - EARLY_SLACK, start + timedelta(minutes=int(s.get("window_minutes", 15)))))
    period_start = min(w[0] for w in windows)
    period_end = max(w[1] for w in windows)

    alerts = []
    for alert in read_jsonl(args.alerts):
        ts = alert.get("timestamp")
        if not ts or not belongs_to_agent(alert, args.agent):
            continue
        when = parse_time(ts)
        if period_start <= when <= period_end:
            alerts.append((when, str(alert.get("rule", {}).get("id", "")), alert))

    used = set()
    results = []
    for s, (start, end) in zip(scenarios, windows):
        expected = SCENARIO_RULES.get(s["scenario"], set())
        match = next(
            (i for i, (when, rule_id, _) in enumerate(alerts) if rule_id in expected and start <= when <= end),
            None,
        )
        if match is not None:
            used.add(match)
        results.append((s, expected, alerts[match] if match is not None else None))

    expected_anywhere = set().union(*SCENARIO_RULES.values())
    unrelated = Counter()
    for i, (_, rule_id, alert) in enumerate(alerts):
        rule = alert.get("rule", {})
        if i in used or rule_id in expected_anywhere or rule_id in args.ignore:
            continue
        if "android" in rule.get("groups", []) and int(rule.get("level", 0)) >= args.min_level:
            unrelated[(rule_id, rule.get("description", ""))] += 1

    print(f"{'Scenario':22} {'Triggered (UTC)':22} {'Expected':16} Result")
    for s, expected, hit in results:
        found = f"rule {hit[1]} at {hit[0].isoformat(timespec='seconds')}" if hit else "NOT DETECTED"
        print(f"{s['scenario']:22} {s['triggered_at']:22} {','.join(sorted(expected)) or '?':16} {found}")

    detected = sum(1 for _, _, hit in results if hit)
    print()
    print(f"Detected {detected} of {len(results)} scenarios ({detected / len(results):.0%}).")
    if unrelated:
        print(f"Unrelated Android alerts of level {args.min_level} or higher in the test period:")
        for (rule_id, description), count in unrelated.most_common():
            print(f"  {count:4}x rule {rule_id}: {description}")
    else:
        print(f"No unrelated Android alerts of level {args.min_level} or higher in the test period.")

    sys.exit(0 if detected == len(results) else 1)


if __name__ == "__main__":
    main()
