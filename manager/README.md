# Manager setup for the Android agent

The phone enrolls and connects like any other agent. The manager needs the rules file,
and optionally an `android` group and an enrollment password.

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

## Test the rules

Paste lines from [`samples/events.jsonl`](samples/events.jsonl) into
`/var/ossec/bin/wazuh-logtest`, or use **Server management > Ruleset test** in the
dashboard.

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
| 100250 | 3 | Network change |
| 100254 | 3 | Network change, including the Wi-Fi name |
| 100251 | 8 | Open or WEP Wi-Fi |
| 100252 | 4 | VPN active |
| 100253 | 5 | Captive portal |
| 100270-100272 | 3-7 | Agent log, warnings/errors, crashes |

Useful dashboard filters: `rule.groups: android`, `rule.groups: android_posture`,
`data.android.type: package`.

## Removing the phone

Remove the agent on the manager (`/var/ossec/bin/manage_agents -r <id>` or the dashboard),
then tap **Forget enrollment** in the app. Re-enrolling under the same name while the old
agent still exists can be refused, depending on the manager's `<force>` settings.
