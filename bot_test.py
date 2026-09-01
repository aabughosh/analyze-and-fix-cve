#!/usr/bin/env python3
"""Tests for CVE package identification (OCPBUGS-113961 / CVE-2026-15792)."""

from __future__ import annotations

import unittest

import bot


def _ticket(**kwargs) -> bot.CVETicket:
    defaults = dict(
        key="OCPBUGS-113961",
        cve_id="CVE-2026-15792",
        summary=(
            "CVE-2026-15792 openshift-kni/commatrix: BuildKit: "
            "Denial of Service via malicious client request [openshift-4.22]"
        ),
        component="networking-ingress-commatrix",
        version="openshift-4.22",
        status="New",
        labels=["pscomponent:openshift-kni/commatrix"],
        upstream_package="",
    )
    defaults.update(kwargs)
    return bot.CVETicket(**defaults)


BUILDKIT_OSV = {
    "aliases": ["GHSA-qx3x-mv6r-52p6"],
    "affected": [
        {
            "ranges": [
                {
                    "type": "GIT",
                    "repo": "https://github.com/moby/buildkit",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "e42e1bfd389af7203238cce77b1f7dad447285e9"},
                    ],
                    "database_specific": {
                        "extracted_events": [
                            {"introduced": "0"},
                            {"fixed": "0.31.2"},
                        ],
                    },
                }
            ],
        }
    ],
}


class PackageResolutionTests(unittest.TestCase):
    def test_jira_upstream_field_wins(self):
        ticket = _ticket(upstream_package="github.com/moby/buildkit")
        pkg = bot.resolve_vulnerable_package(ticket, None)
        self.assertEqual(pkg, "github.com/moby/buildkit")

    def test_osv_git_repo_when_no_go_ecosystem(self):
        packages = bot._packages_from_osv_payload(BUILDKIT_OSV)
        self.assertEqual(packages[0]["name"], "github.com/moby/buildkit")
        self.assertEqual(packages[0]["fixed"], "v0.31.2")

        osv = bot.OSVData(aliases=["GHSA-qx3x-mv6r-52p6"], packages=packages)
        pkg = bot.resolve_vulnerable_package(_ticket(), osv)
        self.assertEqual(pkg, "github.com/moby/buildkit")

    def test_buildkit_keyword_when_jira_and_osv_empty(self):
        pkg = bot.resolve_vulnerable_package(_ticket(), None)
        self.assertEqual(pkg, "github.com/moby/buildkit")

    def test_summary_import_path(self):
        ticket = _ticket(
            summary=(
                "CVE-2026-39829 openshift-kni/commatrix: "
                "golang.org/x/crypto/ssh: Denial of Service [openshift-4.22]"
            ),
            upstream_package="",
        )
        pkg = bot.resolve_vulnerable_package(ticket, None)
        self.assertEqual(pkg, "golang.org/x/crypto/ssh")

    def test_does_not_use_pscomponent_as_package(self):
        ticket = _ticket(summary="CVE-2026-15792 openshift-kni/commatrix: something")
        # No BuildKit keyword in this summary.
        ticket.summary = "CVE-2026-15792 openshift-kni/commatrix: Denial of Service [openshift-4.22]"
        pkg = bot.resolve_vulnerable_package(ticket, None)
        self.assertEqual(pkg, "")

    def test_comment_searches_full_module_not_unknown(self):
        ticket = _ticket(upstream_package="github.com/moby/buildkit")
        package = "github.com/moby/buildkit"
        details = {
            "go_version": "1.24.0",
            "grep_term": package,
            "grep_gomod": "(not found)",
            "grep_gosum": "(not found)",
            "grep_source": "(no source code references found)",
            "govulncheck": "Package github.com/moby/buildkit not in dependency tree",
        }
        comment = bot._build_detailed_comment(
            ticket, "https://github.com/openshift-kni/commatrix",
            "release-4.22", package, "NOT_AFFECTED", details,
        )
        self.assertIn("github.com/moby/buildkit", comment)
        self.assertIn('$ grep -F "github.com/moby/buildkit" go.mod', comment)
        self.assertNotIn('grep -i "unknown"', comment)
        self.assertNotIn("Vulnerable package: N/A", comment)

    def test_comment_skips_grep_when_package_missing(self):
        ticket = _ticket(summary="CVE-2026-0000 foo: no package here [openshift-4.22]")
        comment = bot._build_detailed_comment(
            ticket, "https://github.com/openshift-kni/commatrix",
            "release-4.22", "", "UNKNOWN", {},
        )
        self.assertIn("could not determine", comment)
        self.assertNotIn('grep -i "unknown"', comment)
        self.assertNotIn('grep -F "unknown"', comment)
        self.assertIn("Skipped: no vulnerable package name was identified", comment)

    def test_package_in_gomod_uses_parent_module(self):
        gomod = "require (\n\tgolang.org/x/crypto v0.45.0\n)\n"
        self.assertTrue(bot._package_in_gomod("golang.org/x/crypto/ssh", gomod))
        self.assertFalse(bot._package_in_gomod("github.com/moby/buildkit", gomod))

    def test_buildkit_not_confused_with_moby_spdystream(self):
        gomod = "require github.com/moby/spdystream v0.5.0\nrequire github.com/moby/term v0.5.2\n"
        self.assertFalse(bot._package_in_gomod("github.com/moby/buildkit", gomod))


if __name__ == "__main__":
    unittest.main()
