"""Unit tests for the Android threat-intel integrator. No network."""

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import android_intel


NOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
SIGNER = "67a06c5dd50c716460c8d6314a2070d11211f4f34e122227a3209e24d9bcc1f0"
APK = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def alert(android, agent_name="pixel"):
    return {"agent": {"id": "003", "name": agent_name}, "data": {"android": android}}


class IntelTests(unittest.TestCase):
    def test_virustotal_hit_emits_one_hash_event(self):
        def fetch(url, method="GET", data=None, headers=None):
            self.assertIn("virustotal", url)
            self.assertEqual(headers["x-apikey"], "vt-key")
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 4}}}}

        emitted = []
        with tempfile.TemporaryDirectory() as directory:
            android_intel.run(
                alert({"type": "package", "package": "com.bad.app", "apk_sha256": APK, "signer_sha256": SIGNER}),
                abuse_key="",
                vt_key="vt-key",
                cache_dir=Path(directory),
                emit=emitted.append,
                now=NOW,
                fetch=fetch,
            )
        self.assertEqual([event["indicator_type"] for event in emitted], ["apk_sha256", "signer_sha256"])
        self.assertEqual(emitted[0]["source"], "virustotal")
        self.assertEqual(emitted[0]["package"], "com.bad.app")
        self.assertEqual(emitted[0]["agent_name"], "pixel")

    def test_malwarebazaar_miss_emits_nothing(self):
        def fetch(url, method="GET", data=None, headers=None):
            return {"query_status": "hash_not_found"}

        emitted = []
        with tempfile.TemporaryDirectory() as directory:
            android_intel.run(
                alert({"type": "package", "package": "com.example.tool", "apk_sha256": APK, "signers": [SIGNER]}),
                abuse_key="abuse",
                vt_key="",
                cache_dir=Path(directory),
                emit=emitted.append,
                now=NOW,
                fetch=fetch,
            )
        self.assertEqual(emitted, [])

    def test_clean_hash_is_not_looked_up_again(self):
        calls = []

        def fetch(url, method="GET", data=None, headers=None):
            calls.append(url)
            return {"query_status": "hash_not_found"}

        with tempfile.TemporaryDirectory() as directory:
            for _ in range(2):
                android_intel.run(
                    alert({"type": "package_inventory", "package": "com.example", "apk_sha256": APK}),
                    abuse_key="abuse",
                    vt_key="",
                    cache_dir=Path(directory),
                    emit=lambda event: None,
                    now=NOW,
                    fetch=fetch,
                )
        self.assertEqual(len(calls), 1)

    def test_listed_host_emits_host_event(self):
        def fetch(url, method="GET", data=None, headers=None):
            return {"query_status": "is_host"}

        emitted = []
        with tempfile.TemporaryDirectory() as directory:
            android_intel.run(
                alert({"type": "network_log", "kind": "dns", "package": "com.example.spy", "hostname": "evil.example"}),
                abuse_key="abuse",
                vt_key="",
                cache_dir=Path(directory),
                emit=emitted.append,
                now=NOW,
                fetch=fetch,
            )
        self.assertEqual(emitted[0]["kind"], "host")
        self.assertEqual(emitted[0]["indicator"], "evil.example")
        self.assertEqual(emitted[0]["indicator_type"], "hostname")

    def test_bulletin_lists_cves_fixed_after_the_device_patch(self):
        vulns = [{
            "id": "ASB-A-1",
            "aliases": ["CVE-2024-0001", "CVE-2024-0002"],
            "affected": [{
                "package": {"ecosystem": "Android", "name": "platform/frameworks/base"},
                "ranges": [{"events": [{"introduced": "14:0"}, {"fixed": "14:2024-10-05"}]}],
            }],
        }, {
            "id": "CVE-2024-0003",
            "aliases": [],
            "affected": [{
                "package": {"ecosystem": "Android"},
                "ranges": [{"events": [{"fixed": "14:2024-07-01"}]}],
            }],
        }]

        def fetch(url, method="GET", data=None, headers=None):
            sent = json.loads(data.decode())
            self.assertEqual(sent["version"], "14:2024-08-05")
            return {"vulns": vulns}

        emitted = []
        with tempfile.TemporaryDirectory() as directory:
            android_intel.run(
                alert({"type": "posture", "android_release": "14", "security_patch": "2024-08-05"}),
                abuse_key="",
                vt_key="",
                cache_dir=Path(directory),
                emit=emitted.append,
                now=NOW,
                fetch=fetch,
            )
            android_intel.run(
                alert({"type": "posture", "android_release": "14", "security_patch": "2024-08-05"}),
                abuse_key="",
                vt_key="",
                cache_dir=Path(directory),
                emit=emitted.append,
                now=NOW + timedelta(hours=1),
                fetch=fetch,
            )
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["cves"], ["CVE-2024-0001", "CVE-2024-0002"])
        self.assertEqual(emitted[0]["cve_count"], 2)
        self.assertEqual(emitted[0]["latest_fix"], "2024-10-05")

    def test_current_patch_emits_nothing(self):
        def fetch(url, method="GET", data=None, headers=None):
            return {"vulns": [{
                "id": "ASB-A-1",
                "aliases": ["CVE-2024-0001"],
                "affected": [{"ranges": [{"events": [{"fixed": "14:2024-07-01"}]}]}],
            }]}

        emitted = []
        with tempfile.TemporaryDirectory() as directory:
            android_intel.run(
                alert({"type": "posture", "android_release": "14", "security_patch": "2024-08-05"}),
                abuse_key="",
                vt_key="",
                cache_dir=Path(directory),
                emit=emitted.append,
                now=NOW,
                fetch=fetch,
            )
        self.assertEqual(emitted, [])

    def test_process_start_apk_hash_uses_the_process_name(self):
        def fetch(url, method="GET", data=None, headers=None):
            return {"query_status": "ok", "data": [{}]}

        emitted = []
        with tempfile.TemporaryDirectory() as directory:
            android_intel.run(
                alert({"type": "security_log", "tag": "app_apk_hash", "process": "com.example.tool", "apk_sha256": APK}),
                abuse_key="abuse",
                vt_key="",
                cache_dir=Path(directory),
                emit=emitted.append,
                now=NOW,
                fetch=fetch,
            )
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["package"], "com.example.tool")
        self.assertEqual(emitted[0]["indicator_type"], "apk_sha256")


if __name__ == "__main__":
    unittest.main()
