#!/usr/bin/env bash
# Triggers the Android agent's detections on a phone connected over USB and records when each
# scenario ran, so evaluate.py can match them against the manager's alerts afterwards.
#
# Usage: manager/testing/run_scenarios.sh [scenario_log.jsonl]
#
# Environment:
#   TEST_APK        harmless APK to install and remove over adb (app scenarios are skipped if unset)
#   TEST_PACKAGE    package name of TEST_APK, if it is already installed on the phone
#   WRONG_PIN       PIN typed for the failed-unlock scenario (default 0000; must not be the real PIN)
#   SKIP_UNLOCK=1   skip the failed-unlock scenario (needs a PIN lock and the agent's device admin)
#   DEVICE_OWNER=1  also run the security and network log scenarios (Device Owner phones only)
#   TEST_DOMAIN     domain opened for the network log scenario (default wazuh-android-test.example.com)
#   OFFLINE=1       also cut Wi-Fi and mobile data for OFFLINE_MINUTES (default 15) to test disconnection alerts
#   ADB             adb binary (default adb)

set -euo pipefail

LOG_FILE="${1:-scenario_log.jsonl}"
ADB="${ADB:-adb}"
AGENT_PACKAGE="io.github.hannescoetzee.wazuhagent"

log_scenario() {
  local scenario="$1" window="$2" description="$3" ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"scenario":"%s","triggered_at":"%s","window_minutes":%s,"description":"%s"}\n' \
    "$scenario" "$ts" "$window" "$description" >> "$LOG_FILE"
  echo "[$ts] $scenario: $description"
}

adb_shell() { "$ADB" shell "$@" | tr -d '\r'; }

if [[ "$("$ADB" get-state 2>/dev/null)" != "device" ]]; then
  echo "No phone found. Connect exactly one phone with USB debugging enabled." >&2
  exit 1
fi
if [[ -z "$(adb_shell pm path "$AGENT_PACKAGE")" ]]; then
  echo "The Wazuh agent ($AGENT_PACKAGE) is not installed on this phone." >&2
  exit 1
fi

echo "Logging scenarios to $LOG_FILE"

echo "--- Developer options (rule 100217) ---"
# The toggle in Settings also turns USB debugging off; `settings put` only changes this one value.
adb_shell settings put global development_settings_enabled 0
sleep 5
adb_shell settings put global development_settings_enabled 1
"$ADB" wait-for-device
log_scenario developer_options 15 "Turned developer options off and on again"

if [[ -n "${TEST_APK:-}" ]]; then
  echo "--- App installed and removed over adb (rules 100232, 100233) ---"
  before="$(adb_shell pm list packages -3 | sort)"
  "$ADB" install -r "$TEST_APK" > /dev/null
  log_scenario app_install_adb 15 "Installed $(basename "$TEST_APK") over adb"
  after="$(adb_shell pm list packages -3 | sort)"
  pkg="${TEST_PACKAGE:-$(comm -13 <(echo "$before") <(echo "$after") | sed 's/^package://' | head -1)}"
  if [[ -n "$pkg" ]]; then
    sleep 20
    "$ADB" uninstall "$pkg" > /dev/null
    log_scenario app_removed 15 "Removed $pkg"
  else
    echo "Could not tell which package was installed; set TEST_PACKAGE to test removal."
  fi
else
  echo "--- App scenarios skipped (set TEST_APK) ---"
fi

if [[ "${SKIP_UNLOCK:-0}" != "1" ]]; then
  echo "--- Five failed unlocks (rules 100260, 100261) ---"
  pin="${WRONG_PIN:-0000}"
  size="$(adb_shell wm size | grep -o '[0-9]*x[0-9]*' | tail -1)"
  width="${size%x*}"
  height="${size#*x}"
  adb_shell input keyevent KEYCODE_SLEEP
  sleep 2
  adb_shell input keyevent KEYCODE_WAKEUP
  sleep 1
  for _ in 1 2 3 4 5; do
    adb_shell input swipe $((width / 2)) $((height * 4 / 5)) $((width / 2)) $((height / 5)) 200
    sleep 1
    adb_shell input text "$pin"
    adb_shell input keyevent KEYCODE_ENTER
    sleep 2
  done
  log_scenario failed_unlock 15 "Typed a wrong PIN five times"
  log_scenario unlock_brute_force 15 "Five failed unlocks within five minutes"
  echo "Unlock the phone yourself before the next step (Android locks input for 30 seconds)."
  read -r -p "Press Enter when the phone is unlocked... "
else
  echo "--- Failed unlock scenario skipped ---"
fi

if [[ "${DEVICE_OWNER:-0}" == "1" ]]; then
  echo "--- Device Owner: adb shell in the security log (rule 100241) ---"
  adb_shell id > /dev/null
  # Android releases security log batches on its own schedule, so allow a long window.
  log_scenario adb_shell 180 "Ran an adb shell command"

  echo "--- Device Owner: suspicious domain in the network log (rule 100291) ---"
  domain="${TEST_DOMAIN:-wazuh-android-test.example.com}"
  adb_shell am start -a android.intent.action.VIEW -d "https://$domain/" > /dev/null || true
  log_scenario suspicious_domain 180 "Opened https://$domain in the browser"
fi

if [[ "${OFFLINE:-0}" == "1" ]]; then
  minutes="${OFFLINE_MINUTES:-15}"
  echo "--- Agent offline for $minutes minutes (Wazuh rule 504) ---"
  adb_shell svc wifi disable
  adb_shell svc data disable
  log_scenario agent_offline $((minutes + 15)) "Turned off Wi-Fi and mobile data for $minutes minutes"
  sleep $((minutes * 60))
  adb_shell svc wifi enable
  adb_shell svc data enable
fi

adb_shell input keyevent KEYCODE_HOME
echo
echo "Done. Wait for the agent to send its queue, then copy /var/ossec/logs/alerts/alerts.json"
echo "from the manager and run:"
echo "  python3 manager/testing/evaluate.py --scenarios $LOG_FILE --alerts alerts.json --agent <agent name>"
