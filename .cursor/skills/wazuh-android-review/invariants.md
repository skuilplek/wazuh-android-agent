# Invariants

These are current behavior. A review finding is a change that breaks one, or a fix that would require breaking one without saying so.

## Device admin

`device_admin.xml` uses only `watch-login`. The admin reports failed unlocks. It does not lock, wipe, reset the password, disable the camera, or set password rules. Reject any new `<uses-policies>` child.

## Process

- `AgentForegroundService` is `exported="false"`, `foregroundServiceType="specialUse"`, and `stopWithTask="false"`. The special-use property describes the persistent manager connection.
- `BootReceiver` is `exported="false"` and only starts the service when the agent is enabled and a key exists.
- Stop sets `agentEnabled` false and cancels the restart alarm. `onDestroy` does not clear `agentEnabled` by itself.
- `CollectorManager.start` / `stop` start and stop the live collectors with the service. The UI starts and stops the service. It does not collect.
- `PostureWorker` still runs `PostureCollector`, `PackageCollector.reconcile` and `ProcessCollector` about every 15 minutes while the agent is enabled and enrolled, including when the service is paused. It calls `scheduleRestart`. It does not call `startForegroundService` itself.

## Enrollment and identity

- The key stored at enrollment is what the session uses. Clearing the key stops the agent.
- The pinned certificate SHA-256 from first enrollment is reused. Replacing the pin silently on every connect is a finding.
- The agent version negotiated at enrollment is reused for the startup handshake.

## Events and rules

- Collectors build events with `Events.build`, so the JSON is `{"android": {"type", "event_time", "app_version", ...}}`.
- `EventQueue.truncate` is the exception. Over 20,000 characters it replaces the body with `{"android": {"type", "truncated": true, "original_size"}}` and drops `event_time` and `app_version`. Keep that shape.
- The location string sent to the manager is `android` and must not contain `:`.
- `manager/rules/android_rules.xml` rule `100200` lists the known types: `posture`, `posture_finding`, `posture_change`, `package`, `package_inventory`, `package_summary`, `network`, `agent_log`, `unlock`, `agent_admin`, `security_log`, `network_log`, `process_snapshot`. A new type or a renamed field is incomplete until a rule in `100200`–`100299` matches it.
- Rule IDs stay inside `100200`–`100299`.

## What this app is not

Do not recommend Hilt, Clean Architecture layers, Retrofit, OkHttp, Firebase, or a second networking stack. UI changes stay in the existing Compose screens (`Status`, `Events`, `Settings`) and `MainViewModel`.
