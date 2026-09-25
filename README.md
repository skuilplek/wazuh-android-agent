# Wazuh Android Agent

A native Kotlin agent for non-rooted Android phones. It enrolls with a Wazuh manager
through `wazuh-authd` (TLS, port 1515), then speaks the regular agent protocol to
`wazuh-remoted` (AES, port 1514), so the phone shows up in the dashboard as a normal
active agent.

It reports:

- **Posture**: screen lock, encryption, patch age, developer options, USB and wireless
  debugging, root and emulator indicators, verified boot, and device admin, accessibility
  and notification-listener apps.
- **Apps**: installs, updates and removals, with the installer, sideload flag and granted
  dangerous permissions. The first run after enrollment sends a full inventory.
- **Network**: changes in transport, VPN, addresses, DNS and Wi-Fi security. The Wi-Fi name
  is only included if you grant location permission.
- **Failed unlocks**: each wrong PIN, pattern or password, if you turn on the agent's device
  admin. The manager alerts on 5 failures within 5 minutes.
- **Capabilities**: what the agent can and cannot see on this phone (device admin, Device
  Owner, location, battery exemption), sent with each posture report and shown in the app.
- **Security and network logs** (Device Owner phones only): ADB shell commands, CA
  certificate installs, logging stopped, storage mounts, and DNS lookups and connections per
  app. See [Device Owner mode](#device-owner-mode-optional).
- **Agent log**: the app's own errors and crashes.

Events are queued in a local database while the phone is offline.

## Layout

- `protocol/`: pure Kotlin/JVM implementation of enrollment, key derivation, the message
  codec, framing and the agent session. It has unit tests with vectors that were built
  independently from the Wazuh C sources.
- `app/`: the Android app (Compose UI, foreground service, collectors, Room queue,
  encrypted key storage).
- `manager/`: rules, optional app and domain lists, adb test scenarios and setup notes for
  the Wazuh manager. See [manager/README.md](manager/README.md).
- `provisioning/`: an example QR code payload for Device Owner setup.

## Build

Requirements: JDK 17 and the Android SDK (platform 35).

```sh
brew install openjdk@17
brew install --cask android-commandlinetools
export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0"
echo "sdk.dir=$ANDROID_HOME" > local.properties

./gradlew :protocol:test          # protocol unit tests
./gradlew :app:assembleDebug      # app/build/outputs/apk/debug/wazuh-agent-<version>-debug.apk
```

## Install on the phone

1. On the phone, enable **Developer options > USB debugging** and connect it by USB.
2. Run `$ANDROID_HOME/platform-tools/adb install -r app/build/outputs/apk/debug/wazuh-agent-*-debug.apk`.
3. Open **Wazuh Agent** and enter the manager address. Add the enrollment password if the
   manager uses one, then tap **Enroll**.
4. Allow the notification, and allow the app to run unrestricted in the background so
   Android does not kill the connection.
5. Optionally, tap **Allow** next to **Device admin** to report failed unlock attempts. The
   admin only uses the "watch login" policy: it cannot lock, wipe or change the phone. If it
   is turned off later, the manager gets an alert (rule 100265).

The app pins the manager's enrollment certificate the first time it enrolls. Later
enrollments to the same host must present the same certificate.

There are two versions:

- **App version** (`versionName`+`versionCode` in `app/build.gradle.kts`, for example
  `0.2.0+2`). It is shown in the app, sent in every event as `android.app_version`, and
  sent as the agent label `agent.app_version`. Bump it for each build you install.
- **Wazuh protocol version**, which the app negotiates at enrollment. It picks the newest
  version the manager accepts, because Wazuh rejects agents that are newer than the manager.

Once enrolled, you can turn USB debugging off again. The agent reports it as a posture
finding while it is on.

## Device Owner mode (optional)

On a phone dedicated to the agent, you can make it the Device Owner. The agent then turns on
Android's security log and network log. It sets no other policy. This needs a factory-reset
phone with no Google or other accounts added.

With adb, after installing the app on the freshly reset phone:

```sh
adb shell dpm set-device-owner io.github.hannescoetzee.wazuhagent/.admin.AgentDeviceAdminReceiver
```

Then open the app and enroll as usual. The **Capabilities** card shows whether the security
and network logs are on. Android delivers both logs in batches, often an hour or more apart,
so these events arrive late. DNS lookups and connections are grouped per app and
destination in each batch.

To remove Device Owner, factory-reset the phone.

### QR provisioning

Instead of adb, a factory-reset phone can be set up from a QR code. It downloads the app, makes
it Device Owner and enrolls with the manager without anyone typing the settings.

1. Build a release APK and host it at an HTTPS URL the phone can reach.
2. Copy [`provisioning/qr_payload.example.json`](provisioning/qr_payload.example.json) and
   fill in:
   - `PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION`: the APK URL.
   - `PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM`: the SHA-256 of the signing certificate,
     base64url-encoded:
     ```sh
     apksigner verify --print-certs app-release.apk | grep 'SHA-256' | head -1 | awk '{print $NF}' \
       | xxd -r -p | base64 | tr '+/' '-_' | tr -d '='
     ```
   - The admin extras: `manager_host`, `enroll_port`, `agent_port`, `enrollment_password`,
     `groups`, and optionally `agent_name` and `keepalive_seconds`.
   - `manager_cert_sha256`: the SHA-256 of the manager's authd certificate, so the first
     enrollment is pinned instead of trusting whatever certificate it sees. Get it with
     `openssl x509 -in /var/ossec/etc/sslmanager.cert -noout -fingerprint -sha256`.
     Remove the key to trust the first certificate instead.
3. Turn the JSON into a QR code (for example `qrencode -o payload.png < payload.json`).
4. On the phone's welcome screen, tap six times to open the QR reader and scan the code.

If enrollment fails during setup (for example, the manager is not reachable yet), the
settings are kept and you can tap **Enroll** in the app later.

## Live protocol test (optional)

This enrolls a throwaway agent against a real manager:

```sh
WAZUH_MANAGER=192.168.1.10 WAZUH_PASSWORD=secret ./gradlew :protocol:test --tests '*LiveManagerTest*'
```

## Limitations

Without root, the agent cannot read the system logcat, monitor system file integrity, or
see other apps' data. Security log and network log events need Device Owner mode, which
needs a factory-reset phone. Failed unlocks are only reported while the agent's device
admin is on. Remote upgrades (WPK), active response and remote configuration
queries are not supported. Some OEM builds kill background services aggressively even with
the battery exemption. On those phones, also allow-list the app in the vendor's battery
settings.
