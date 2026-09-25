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
- **Agent log**: the app's own errors and crashes.

Events are queued in a local database while the phone is offline.

## Layout

- `protocol/`: pure Kotlin/JVM implementation of enrollment, key derivation, the message
  codec, framing and the agent session. It has unit tests with vectors that were built
  independently from the Wazuh C sources.
- `app/`: the Android app (Compose UI, foreground service, collectors, Room queue,
  encrypted key storage).
- `manager/`: rules and setup notes for the Wazuh manager. See
  [manager/README.md](manager/README.md).

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

## Live protocol test (optional)

This enrolls a throwaway agent against a real manager:

```sh
WAZUH_MANAGER=192.168.1.10 WAZUH_PASSWORD=secret ./gradlew :protocol:test --tests '*LiveManagerTest*'
```

## Limitations

Without root, the agent cannot read the system logcat, monitor system file integrity, or
see other apps' data. Remote upgrades (WPK), active response and remote configuration
queries are not supported. Some OEM builds kill background services aggressively even with
the battery exemption. On those phones, also allow-list the app in the vendor's battery
settings.
