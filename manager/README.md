# Manager setup for the Android agent

The phone enrolls and connects like any other agent. The manager needs the rules file,
and optionally an `android` group, an enrollment password and the app and domain lists.

## 1. Create the agent group (optional)

The app enrolls without a group unless you fill in the Groups field. Enrollment fails
with `Invalid group` if a group you enter does not exist, so create it first:

```sh
/var/ossec/bin/agent_groups -a -g android -q
```

## 2. Install the rules

```sh
cp rules/android_rules.xml /var/ossec/etc/rules/android_rules.xml
chown wazuh:wazuh /var/ossec/etc/rules/android_rules.xml   # ossec:ossec on older installs
chmod 660 /var/ossec/etc/rules/android_rules.xml
/var/ossec/bin/wazuh-control restart
```

With the Docker deployment, copy the file into the `wazuh.manager` container (or the
`wazuh_etc` volume) and restart the container.

No decoder file is needed. Events are plain JSON with an `android` root object, which the
stock `json` decoder parses into fields such as `android.type`, `android.check` and
`android.package`. A custom JSON decoder would never be selected, because the stock one
matches every log that starts with `{"`.

## 3. Enrollment password (optional)

If `<auth><use_password>yes</use_password></auth>` is set in `ossec.conf`, enter the
contents of `/var/ossec/etc/authd.pass` in the app's password field.

## 4. App and domain lists (optional)

[`rules/android_rules_lists.xml`](rules/android_rules_lists.xml) checks events against four
CDB lists that you keep on the manager:

| List | Rule | Alert |
|------|------|-------|
| `android_blocked_apps` | 100290, 100292 | A listed app is installed, updated or present (level 12) |
| `android_blocked_signers` | 100293, 100294 | A listed signer SHA-256 is installed, updated or present (level 12) |
| `android_approved_apps` | 100238, 100239 | A user app that is not listed is installed (level 8) or present (level 5) |
| `android_suspicious_domains` | 100291 | An app looks up a listed hostname (Device Owner only, level 10) |

Each line is `key:value`, where the key is a package name, a lowercase signer SHA-256, or a
hostname and the value is an optional note. Hostnames must match exactly; subdomains are not
included. Start from the
samples in [`lists/`](lists/):

```sh
cp lists/android_* /var/ossec/etc/lists/
chown wazuh:wazuh /var/ossec/etc/lists/android_*
```

Declare the lists in the `<ruleset>` section of `/var/ossec/etc/ossec.conf`:

```xml
<list>etc/lists/android_approved_apps</list>
<list>etc/lists/android_blocked_apps</list>
<list>etc/lists/android_blocked_signers</list>
<list>etc/lists/android_suspicious_domains</list>
```

Then install the rules file and restart. It must load after `android_rules.xml`, which its
file name ensures (the manager loads rule files in alphabetical order).

```sh
cp rules/android_rules_lists.xml /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/rules/android_rules_lists.xml
/var/ossec/bin/wazuh-control restart
```

The approved list is only useful once it contains the apps already on your phones.
Otherwise every user app raises rule 100239 on the first inventory. To build it from the
inventory the phones have already sent:

```sh
jq -r 'select(.data.android.type == "package_inventory" and (.data.android.system_app | tostring) == "false")
       | .data.android.package + ":"' /var/ossec/logs/alerts/alerts.json | sort -u
```

## 5. Threat intel and Device Owner commands (optional)

[`integrations/custom-android-intel`](integrations/custom-android-intel) looks up APK and signer
hashes, DNS names and connection addresses, and Android bulletin CVEs for the phone's
`security_patch`. Copy it and `android_intel.py` into the manager's integrations directory
and restart:

```sh
cp integrations/custom-android-intel integrations/android_intel.py /var/ossec/integrations/
chown root:wazuh /var/ossec/integrations/custom-android-intel /var/ossec/integrations/android_intel.py
chmod 750 /var/ossec/integrations/custom-android-intel /var/ossec/integrations/android_intel.py
```

`api_key` is an abuse.ch Auth-Key, used for MalwareBazaar and URLhaus. To also ask
VirusTotal, set `hook_url` to `vt:` followed by the VirusTotal key. Leave it as a normal
URL when you are not using VirusTotal. Hits are written back through the analysisd queue
as `threat_intel` events (rules 100225–100228), attributed with `android.agent_name`.

```xml
<integration>
  <name>custom-android-intel</name>
  <api_key>ABUSECH_AUTH_KEY</api_key>
  <hook_url>https://mb-api.abuse.ch/api/v1/</hook_url>
  <!-- The alert id is the rule that fired. Child rules replace their parent, so both are listed. -->
  <rule_id>100210</rule_id>
  <rule_id>100230</rule_id>
  <rule_id>100231</rule_id>
  <rule_id>100232</rule_id>
  <rule_id>100234</rule_id>
  <rule_id>100235</rule_id>
  <rule_id>100236</rule_id>
  <rule_id>100238</rule_id>
  <rule_id>100239</rule_id>
  <rule_id>100256</rule_id>
  <rule_id>100257</rule_id>
  <rule_id>100268</rule_id>
  <rule_id>100290</rule_id>
  <rule_id>100291</rule_id>
  <rule_id>100292</rule_id>
  <rule_id>100293</rule_id>
  <rule_id>100294</rule_id>
  <alert_format>json</alert_format>
</integration>
```

Device Owner phones accept only these active-response command names. Wazuh appends a
timeout suffix (`android-lock0`); the phone strips it. Any other command, including
`restart-wazuh` and `firewall-drop`, is ignored. The phone does not run a shell.

| Command | Effect |
|---------|--------|
| `android-suspend` / `android-unsuspend` | Suspend or restore one app |
| `android-hide` / `android-unhide` | Hide or show one app |
| `android-clear` | Clear one app's data (Android 9+) |
| `android-uninstall` | Uninstall one app |
| `android-lock` | Lock the phone. Extra arguments are the lock-screen message |
| `android-locate` | Grant location for this command, send a fix or two, then revoke it |
| `android-wipe` | Factory reset, only if the extra arguments include `confirm-wipe` |

The package name comes from an extra argument or from `data.android.package` on the alert.
Do not bind `android-wipe` to a rule. Run it by hand when a wipe is actually required.
Suspend or lock is the command to attach to a malware rule.

```xml
<command>
  <name>android-suspend</name>
  <executable>android-suspend</executable>
  <timeout_allowed>no</timeout_allowed>
</command>
<active-response>
  <disabled>no</disabled>
  <command>android-suspend</command>
  <location>local</location>
  <rules_id>100226</rules_id>
</active-response>
```

The executable name is not a script on the phone. The phone matches the command name.

## Offline phones

No extra component is needed. The phone keeps a regular agent session, so the manager marks
it disconnected once keepalives stop (after `<agents_disconnection_time>` in the `<global>`
section, 10 minutes by default) and raises Wazuh rule 504, "Wazuh agent disconnected". That
rule is level 3; override it in `local_rules.xml` if you want a louder alert.

## Test the rules

Paste lines from [`samples/events.jsonl`](samples/events.jsonl) into
`/var/ossec/bin/wazuh-logtest`, or use **Server management > Ruleset test** in the
dashboard.

To test end to end on a real phone, [`testing/run_scenarios.sh`](testing/run_scenarios.sh)
uses adb to trigger the detections: developer options, an app installed and removed over
adb, five wrong PINs and, on a Device Owner phone, an adb shell command and a lookup of the
test domain in `android_suspicious_domains`. It records when each scenario ran. Afterwards,
[`testing/evaluate.py`](testing/evaluate.py) checks the manager's alerts for the expected
rule within each scenario's time window:

```sh
TEST_APK=path/to/harmless.apk manager/testing/run_scenarios.sh scenario_log.jsonl
# copy /var/ossec/logs/alerts/alerts.json from the manager, then:
python3 manager/testing/evaluate.py --scenarios scenario_log.jsonl --alerts alerts.json --agent <agent name>
```

The script header lists the options (`WRONG_PIN`, `SKIP_UNLOCK`, `DEVICE_OWNER`, `OFFLINE`).
The failed-unlock scenario needs a PIN lock and the agent's device admin turned on.

## Rule reference

| ID | Level | Fires on |
|----|-------|----------|
| 100210 | 3 | Posture report (every change, at least every 6 hours) |
| 100212 | 10 | No screen lock |
| 100213 | 10 | Storage encryption inactive or unsupported |
| 100214 | 12 | Root indicators found |
| 100215 | 10 | Wireless debugging enabled |
| 100216 | 8 | USB debugging enabled |
| 100217 | 5 | Developer options enabled |
| 100218 | 7 | Security patch older than 90 days |
| 100219 | 10 | Verified boot state orange, yellow or red |
| 100220 | 5 | Running on an emulator |
| 100222 | 9 | Accessibility services changed |
| 100223 | 9 | Device admin apps changed |
| 100224 | 7 | Apps able to install other apps changed |
| 100230 | 3 | App installed, updated or removed |
| 100231 | 8 | App installed or updated from outside an app store |
| 100232 | 9 | App installed over ADB |
| 100233 | 5 | Non-store app removed |
| 100234 | 7 | Debuggable app installed |
| 100235 | 3 | App inventory entry (first run after enrollment) |
| 100236 | 6 | Inventory entry not installed from an app store |
| 100237 | 3 | Daily app summary |
| 100238 | 8 | App installed that is not on the approved list (lists file) |
| 100239 | 5 | Inventory entry not on the approved list (lists file) |
| 100240 | 3 | Security log entry (Device Owner) |
| 100241 | 10 | ADB shell command |
| 100242 | 10 | Interactive ADB shell |
| 100243 | 10 | File pulled or pushed over ADB |
| 100244 | 10 | CA certificate installed |
| 100245 | 5 | CA certificate removed |
| 100246 | 12 | Security logging stopped |
| 100247 | 10 | Key integrity violation, wipe failure or full log buffer |
| 100248 | 10 | Cryptographic self-test failed |
| 100249 | 5 | External storage mounted |
| 100266 | 5 | Backup service toggled |
| 100267 | 6 | Keystore key imported |
| 100268 | 5 | APK hash from the security log is new or changed |
| 100250 | 3 | Network change |
| 100254 | 3 | Network change, including the Wi-Fi name |
| 100251 | 8 | Open or WEP Wi-Fi |
| 100252 | 4 | VPN active |
| 100253 | 5 | Captive portal |
| 100256 | 3 | DNS lookup by an app (Device Owner, one per app and hostname per batch) |
| 100257 | 3 | Connection by an app (Device Owner, one per app and destination per batch) |
| 100260 | 5 | Failed unlock attempt (agent device admin) |
| 100261 | 10 | 5 failed unlocks within 5 minutes |
| 100262 | 10 | 10 or more failed unlocks in a row |
| 100263 | 3 | Unlocked after failed attempts |
| 100264 | 3 | Agent device admin turned on |
| 100265 | 10 | Agent device admin turned off |
| 100270-100272 | 3-7 | Agent log, warnings/errors, crashes |
| 100225 | 3 | Threat-intel result from the integrator |
| 100226 | 12 | MalwareBazaar or VirusTotal matched an APK or signer hash |
| 100227 | 10 | URLhaus listed a DNS name or connection address |
| 100228 | 8 | Android security patch is missing bulletin CVEs |
| 100273 | 3 | Device Owner command result |
| 100274 | 5 | Device Owner command failed or was refused |
| 100275 | 12 | Device wipe started |
| 100276 | 8 | Device locked |
| 100281 | 3 | Location sent for an android-locate command |
| 100285 | 3 | Memory and process snapshot (about every 15 minutes) |
| 100286 | 7 | Device is low on memory |
| 100287 | 5 | Memory 90% or more used |
| 100290 | 12 | Blocked app installed or updated (lists file) |
| 100291 | 10 | DNS lookup of a suspicious domain (lists file) |
| 100292 | 12 | Blocked app present in inventory (lists file) |
| 100293 | 12 | Blocked signer installed or updated (lists file) |
| 100294 | 12 | Blocked signer present in inventory (lists file) |

If DNS and connection alerts are too many, lower 100256 and 100257 to level 0. Rule 100291
still works, because it only needs the rules to match, not to raise an alert.

Rule 100285 fires about every 15 minutes, roughly 96 times a day per phone. Lower it to
level 0 if that is too many. Rules 100286 and 100287 still alert, because they only need
100285 to match.

## Dashboard queries

In **Discover** on `wazuh-alerts-*`, these queries cover the common questions:

| Question | Query |
|----------|-------|
| Everything from the Android agent | `rule.groups: android` |
| Stalkerware signals (accessibility, device admin changes) | `rule.groups: android_stalkerware` |
| Possible lost or stolen phones | `rule.id: (100261 or 100262)` |
| Agent device admin turned off | `rule.groups: android_tamper` |
| Unapproved or blocked apps | `rule.groups: (android_unapproved_app or android_blocked_app)` |
| Sideloaded apps | `rule.groups: android_sideload` |
| Phones without the agent's device admin | `data.android.type: posture and data.android.capabilities.device_admin.available: false` |
| CA certificates installed | `rule.id: 100244` |
| DNS lookups by one app | `rule.id: 100256 and data.android.package: "com.example.app"` |
| Disconnected phones | `rule.id: 504` |
| Phones low on memory | `rule.id: 100286` |
| Memory 90% or more used | `rule.id: 100287` |
| Process list on a rooted phone | `data.android.type: process_snapshot and data.android.source: root` |
| Hash or host threat intel | `rule.id: (100226 or 100227)` |
| Missing Android bulletin CVEs | `rule.id: 100228` |
| Device Owner command results | `rule.id: (100273 or 100274 or 100275 or 100276)` |

`data.android.top_processes` on a rooted phone lists the processes using the most memory,
for example `com.android.systemui 412MB`. Without root, `data.android.recent_apps` and
`data.android.foreground_app` come from Usage Access.

For a per-phone overview, build a data table visualization with a terms split on `agent.name`
and a filter of `rule.groups: android and rule.level >= 7`. For patch levels, use a terms split
on `agent.name` and `data.android.security_patch` with the filter `rule.id: 100210`.

## Removing the phone

Remove the agent on the manager (`/var/ossec/bin/manage_agents -r <id>` or the dashboard),
then tap **Forget enrollment** in the app. Re-enrolling under the same name while the old
agent still exists can be refused, depending on the manager's `<force>` settings.
