# Rapid7 Recog fingerprints (vendored data)

The XML fingerprint databases of [Rapid7 Recog](https://github.com/rapid7/recog), pinned to commit
[`f1191e24332c51d6a3d98457f64fba8dec340784`](https://github.com/rapid7/recog/tree/f1191e24332c51d6a3d98457f64fba8dec340784) (2026-11-12T10:04:49Z). Recog is under the BSD 2-Clause license: `LICENSE` and `COPYING` in this
folder are Recog's own (Copyright (c) 2014-2015, Rapid7).

Only the databases `cveFeed.recog` reads are kept, unchanged, with no Ruby code: `http_servers.xml`, `http_cookies.xml`, `ssh_banners.xml`, `smtp_banners.xml`, `ftp_banners.xml`, `snmp_sysdescr.xml`, `telnet_banners.xml`, `pop_banners.xml`, `imap_banners.xml`, `mysql_banners.xml`, `ntp_banners.xml`.
`manifest.json` records the commit and the SHA-256 of every file; the tests check both, and check that every fingerprint cvENGINE loads
matches Recog's own `<example>` entries.

Refresh with `python3 scripts/update_recog.py <commit>` (it downloads that commit's files from GitHub), review the diff, run
`python3 manage.py test tests.test_recog` and commit. Nothing reads the network at run time or in CI.
