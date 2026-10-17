"""Lookups for Android agent alerts. The Wazuh integrator runs custom-android-intel."""

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

QUEUE_SOCKET = "/var/ossec/queue/sockets/queue"
CACHE_DIR = Path("/var/ossec/var/wazuh-android")
HASH_TTL = timedelta(days=7)
BULLETIN_TTL = timedelta(hours=24)
CVE_LIMIT = 25
OSV_URL = "https://api.osv.dev/v1/query"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
TIMEOUT_SECONDS = 20


def main(argv):
    if len(argv) < 2:
        return 0
    try:
        alert = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    abuse_key = argv[2] if len(argv) > 2 else ""
    hook = argv[3] if len(argv) > 3 else ""
    vt_key = hook[3:] if hook.startswith("vt:") else ""
    try:
        run(alert, abuse_key=abuse_key, vt_key=vt_key, cache_dir=CACHE_DIR, emit=emit_queue)
    except Exception as error:
        log(f"android-intel failed: {error}")
    return 0


def run(alert, abuse_key, vt_key, cache_dir, emit, now=None, fetch=None):
    now = now or datetime.now(timezone.utc)
    fetch = fetch or http_json
    android = android_fields(alert)
    kind = android.get("type")
    apk_from_log = kind == "security_log" and android.get("tag") == "app_apk_hash"
    if kind in ("package", "package_inventory") or apk_from_log:
        lookup_hashes(alert, android, abuse_key, vt_key, cache_dir, emit, now, fetch)
    elif kind == "network_log":
        lookup_host(alert, android, abuse_key, cache_dir, emit, now, fetch)
    elif kind == "posture":
        lookup_bulletin(alert, android, cache_dir, emit, now, fetch)


def lookup_hashes(alert, android, abuse_key, vt_key, cache_dir, emit, now, fetch):
    if not abuse_key and not vt_key:
        return
    package = android.get("package") or android.get("process") or ""
    hashes = []
    apk = android.get("apk_sha256") or ""
    if is_sha256(apk):
        hashes.append(("apk_sha256", apk))
    for signer in signer_list(android):
        hashes.append(("signer_sha256", signer))
    cache = Cache(cache_dir / "hash-cache.json")
    for indicator_type, digest in hashes:
        source = cache.get(digest, now, HASH_TTL)
        if source is None:
            source = hash_reputation(digest, abuse_key, vt_key, fetch)
            if source is None:
                continue
            cache.put(digest, source, now)
        if source != "clean":
            emit(threat_event(alert, "hash", source, digest, indicator_type, package=package, now=now))


def lookup_host(alert, android, abuse_key, cache_dir, emit, now, fetch):
    if not abuse_key:
        return
    if android.get("kind") == "dns":
        indicator = android.get("hostname") or ""
    else:
        indicator = android.get("ip") or ""
    if not usable_host(indicator):
        return
    cache = Cache(cache_dir / "host-cache.json")
    cached = cache.get(indicator, now, HASH_TTL)
    listed = cached
    if listed is None:
        listed = host_is_listed(indicator, abuse_key, fetch)
        if listed is None:
            return
        cache.put(indicator, listed, now)
    if listed:
        emit(
            threat_event(
                alert, "host", "urlhaus", indicator, "hostname" if android.get("kind") == "dns" else "ip",
                package=android.get("package") or "", now=now,
            )
        )


def lookup_bulletin(alert, android, cache_dir, emit, now, fetch):
    release = str(android.get("android_release") or "")
    patch = str(android.get("security_patch") or "")
    if not release or not is_patch_date(patch):
        return
    key = f"{release}|{patch}"
    cache = Cache(cache_dir / "bulletin-cache.json")
    if cache.get(key, now, BULLETIN_TTL) is not None:
        return
    vulns = fetch_osv(release, patch, fetch)
    if vulns is None:
        return
    cves, latest = cves_after_patch(vulns, release, patch)
    cache.put(key, True, now)
    if not cves:
        return
    event = threat_event(alert, "bulletin", "osv", patch, "security_patch", now=now)
    event["android_release"] = release
    event["security_patch"] = patch
    event["cve_count"] = len(cves)
    event["cves"] = cves[:CVE_LIMIT]
    if latest:
        event["latest_fix"] = latest
    emit(event)


def hash_reputation(digest, abuse_key, vt_key, fetch):
    """Feed name when a lookup hits, \"clean\" when every lookup misses, None when all of them fail."""
    answered = False
    if abuse_key:
        body = fetch(
            MALWAREBAZAAR_URL,
            method="POST",
            data=urllib.parse.urlencode({"query": "get_info", "hash": digest}).encode(),
            headers={"Auth-Key": abuse_key, "Content-Type": "application/x-www-form-urlencoded"},
        )
        if body is not None:
            answered = True
            if body.get("query_status") == "ok":
                return "malwarebazaar"
    if vt_key:
        body = fetch(
            f"https://www.virustotal.com/api/v3/files/{digest}",
            headers={"x-apikey": vt_key},
        )
        if body is not None:
            answered = True
            stats = ((body.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
            if stats.get("malicious", 0) > 0:
                return "virustotal"
    if not answered:
        return None
    return "clean"


def host_is_listed(host, abuse_key, fetch):
    body = fetch(
        URLHAUS_HOST_URL,
        method="POST",
        data=urllib.parse.urlencode({"host": host}).encode(),
        headers={"Auth-Key": abuse_key, "Content-Type": "application/x-www-form-urlencoded"},
    )
    if body is None:
        return None
    return body.get("query_status") == "is_host"


def fetch_osv(release, patch, fetch):
    major = release.split(".")[0]
    body = fetch(
        OSV_URL,
        method="POST",
        data=json.dumps({
            "package": {"ecosystem": "Android", "name": "platform/frameworks/base"},
            "version": f"{major}:{patch}",
        }).encode(),
        headers={"Content-Type": "application/json"},
    )
    if body is None:
        return None
    return body.get("vulns") or []


def cves_after_patch(vulns, release, patch):
    """CVEs whose Android fix date for this major is after the device patch."""
    major = release.split(".")[0]
    found = []
    latest = ""
    for vuln in vulns:
        fixed = fixed_dates(vuln, major)
        if not fixed:
            continue
        newest = max(fixed)
        if patch >= newest:
            continue
        if newest > latest:
            latest = newest
        found.extend(cve_ids(vuln))
    unique = []
    for cve in found:
        if cve not in unique:
            unique.append(cve)
    unique.sort()
    return unique, latest


def fixed_dates(vuln, major):
    dates = []
    prefix = major + ":"
    for affected in vuln.get("affected") or []:
        package = affected.get("package") or {}
        if package.get("ecosystem") not in (None, "Android"):
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                fixed = str(event.get("fixed") or "")
                if fixed.startswith(prefix) and is_patch_date(fixed.split(":", 1)[1][:10]):
                    dates.append(fixed.split(":", 1)[1][:10])
        spl = (affected.get("ecosystem_specific") or {}).get("spl")
        if isinstance(spl, str) and is_patch_date(spl[:10]):
            dates.append(spl[:10])
    return dates


def cve_ids(vuln):
    ids = [alias for alias in vuln.get("aliases") or [] if str(alias).startswith("CVE-")]
    own = str(vuln.get("id") or "")
    if own.startswith("CVE-") and own not in ids:
        ids.append(own)
    return ids


def android_fields(alert):
    data = alert.get("data") or {}
    if isinstance(data.get("android"), dict):
        return data["android"]
    return data if isinstance(data, dict) else {}


def signer_list(android):
    signers = []
    primary = android.get("signer_sha256") or ""
    if is_sha256(primary):
        signers.append(primary)
    extra = android.get("signers") or []
    if isinstance(extra, list):
        for item in extra:
            if is_sha256(item) and item not in signers:
                signers.append(item)
    return signers


def threat_event(alert, kind, source, indicator, indicator_type, package="", now=None):
    now = now or datetime.now(timezone.utc)
    agent = alert.get("agent") or {}
    event = {
        "type": "threat_intel",
        "event_time": now.astimezone().isoformat(timespec="seconds"),
        "kind": kind,
        "source": source,
        "indicator": indicator,
        "indicator_type": indicator_type,
        "agent_id": str(agent.get("id") or ""),
        "agent_name": str(agent.get("name") or ""),
    }
    if package:
        event["package"] = package
    return event


def emit_queue(event):
    payload = json.dumps({"android": event}, separators=(",", ":"))
    message = f"1:android-intel:{payload}".encode()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.connect(QUEUE_SOCKET)
        sock.send(message)
    finally:
        sock.close()


def http_json(url, method="GET", data=None, headers=None):
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {}
        log(f"android-intel HTTP {error.code} for {url}")
        return None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        log(f"android-intel request failed for {url}: {error}")
        return None


def is_sha256(value):
    text = str(value)
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def is_patch_date(value):
    text = str(value)
    if len(text) != 10 or text[4] != "-" or text[7] != "-":
        return False
    return text[:4].isdigit() and text[5:7].isdigit() and text[8:10].isdigit()


def usable_host(value):
    text = str(value)
    return 0 < len(text) <= 253 and " " not in text and "/" not in text and "@" not in text


class Cache:
    def __init__(self, path):
        self.path = Path(path)
        self.data = {}
        if self.path.is_file():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self.data = {}

    def get(self, key, now, ttl):
        entry = self.data.get(key)
        if not isinstance(entry, dict):
            return None
        try:
            seen = datetime.fromisoformat(entry["at"])
        except (KeyError, ValueError):
            return None
        if now - seen > ttl:
            return None
        return entry.get("value")

    def put(self, key, value, now):
        self.data[key] = {"at": now.isoformat(), "value": value}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data), encoding="utf-8")
        except OSError as error:
            log(f"android-intel could not write {self.path}: {error}")


def log(message):
    line = message.rstrip() + "\n"
    try:
        with open("/var/ossec/logs/integrations.log", "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        pass
