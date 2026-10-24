# Reviewed detector fixtures

An AI-generated Nuclei draft stays uninstalled until a maintainer adds a
`CVE-YYYY-NNNN.json` file here and runs
`python manage.py review_generated_template <GeneratedTemplate ID>`.

The JSON must contain exactly `cve_id`, `source_url`, `reviewed_by`, `positive`,
and `negative`. Each response has `status`, `body`, and `headers`. The source
must be an HTTPS advisory or reproducible test reference. Positive and negative
responses must be independently justified and differ in the CVE-specific
feature the detector tests. Do not put real customer responses, credentials, or
private service data in this directory.

The approval command reruns the static policy and Nuclei syntax gates, then
serves each response over loopback. The detector must match the positive case
and miss the negative case. It supports only a single fixed-path, read-only HTTP
request with bounded response matchers. Network, DNS, raw HTTP, redirects and
dynamic paths remain unsupported by this fixture harness. No fixture is bundled
for an actual CVE; a generic example would create false confidence.

Passing these fixtures means the template discriminated the reviewed responses.
It does not establish product presence or vulnerability on a customer host.

The CI job runs `web/tests/nuclei_fixture_smoke.py` with a checksum-pinned
ProjectDiscovery Nuclei binary. Its deliberately generic marker exercises the
same syntax and positive/negative loopback path without approving any CVE.
