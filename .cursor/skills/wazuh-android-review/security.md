# Security

Review only the areas this agent actually has. Skip authentication flows and tamper resistance unless the diff adds them.

## Storage

- The agent key, enrollment password, and certificate pin live in `SecureStore` (`EncryptedSharedPreferences`, Keystore AES-256-GCM). A new secret in plain `SharedPreferences`, a file, or a log line is a finding.
- `allowBackup` stays false. `data_extraction_rules.xml` keeps excluding shared preferences, databases, and files from cloud backup and device transfer. Do not narrow those excludes.
- The Room queue holds event JSON, which can include posture and network data. Do not log queue payloads, `AgentKey`, the enrollment password, or the raw AES key. `AgentLog` messages stay free of those values.
- `androidx.security.crypto` is deprecated. Replacing it is a separate change with a migration of existing prefs. Do not swap it for plaintext storage in a review fix.

## Crypto

- `MessageCodec` matches the Wazuh C client: `AES/CBC/PKCS5Padding` and the fixed IV `FEDCBA0987654321`. Changing the transformation, IV, header (`#AES:`), MD5 framing, or compression is a protocol break. It needs new unit tests whose vectors were produced independently of this encoder.
- Do not "upgrade" this cipher to GCM or a random IV inside the existing session. The manager would not decrypt it.
- Key bytes come from `KeyDerivation`. Do not derive a second key, log key material, or persist the raw key outside `SecureStore`.

## Network

- Enrollment TLS is trust on first use. `PinningTrustManager` records the leaf SHA-256. A null pin may accept the leaf once. A non-null pin must reject a mismatch before the enrollment password is sent.
- A `TrustManager` that accepts every certificate, an empty `checkServerTrusted`, or a hostname verifier that returns true is a finding. `checkClientTrusted` stays a rejection.
- Enrollment to `wazuh-authd` (port 1515) is TLS. The session to `wazuh-remoted` (port 1514) is TCP plus the AES codec in `MessageCodec`. Do not wrap port 1514 in TLS. No cleartext HTTP, and no `usesCleartextTraffic="true"`.
- Enrollment request building rejects newlines in the password and quotes in groups. Keep that. Do not put the password in a query string, Intent extra, or notification.

## Platform

- `AgentForegroundService` and `BootReceiver` stay `exported="false"`. `MainActivity` is the only exported launcher. `ProvisioningActivity` and `AgentDeviceAdminReceiver` stay exported only with `android.permission.BIND_DEVICE_ADMIN`.
- A new `exported="true"` component without a signature or system permission is a finding. Pending intents stay `FLAG_IMMUTABLE`. The uninstall result in `DeviceCommands` is the exception: `PackageInstaller` writes the status into the intent, which an immutable PendingIntent drops. That intent is limited to the agent package and the receiver is not exported.
- A new permission needs a collector or service behavior that requires it. `QUERY_ALL_PACKAGES` is the package inventory. Location is the Wi-Fi name. Exact-alarm and battery permissions are the background restart. Do not add SMS, contacts, microphone, camera, or overlay permissions.
- `device_admin.xml` is covered by [invariants.md](invariants.md). Device Owner logging is enabled only from `DeviceOwner.enableLogging` while `isDeviceOwner` is true.

## Privacy

- `wifi_ssid` and `wifi_bssid` are added only when location is granted and the SSID is not unknown. Do not send them from another path.
- `SecurityLogCollector` and `NetworkLogCollector` return immediately when the app is not Device Owner. Do not call the security or network log APIs otherwise.
- Events are `{"android": {"type": ...}}` with location `android`. Do not add account names, phone numbers, serials, IMEI, or Android ID. Posture does not send those. A new identifier needs a matching rule and a reason in the event.
