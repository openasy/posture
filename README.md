# posture

[![CI](https://github.com/openasy/posture/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/posture/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Posture product: **which controls fail** in a cloud account, a Kubernetes
cluster or a group of hosts, kept per target with a score over time (ADR 0045). Your pipeline runs
[Trivy](https://github.com/aquasecurity/trivy), [kubescape](https://github.com/kubescape/kubescape),
[checkov](https://github.com/bridgecrewio/checkov), [Prowler](https://github.com/prowler-cloud/prowler) or another
checker that writes [SARIF](https://sarifweb.azurewebsites.net/) and sends the report here.

```
CI: trivy config --format sarif  ──POST /api/v1/scans──▶  posture  ──▶  { score, new, resolved, blocking, passed }
                                                              └── targets, failed controls, decisions, score history
```

posture reads reports and nothing else: it holds no checker and reads no cloud account or cluster. Checkers that run for
you come later (ADR 0045).

## Targets

A **target** has a name, a kind (`cloud`, `kubernetes` or `host`) and an optional benchmark label such as
`CIS Kubernetes 1.9`. Admins add them; reports are accepted only for targets that exist.

## How a report is compared

- A report belongs to an **engine** (`trivy`, `kubescape`, or the `engine` you send). Its reports replace each other:
  a control that stops failing is marked fixed, and opens again if it fails again. Engines do not fix each other's
  findings.
- The **first report** of an engine for a target adopts what is there and never fails a check. Later reports fail it
  for **new** failed controls at or above the target's **fail on** severity (high by default) that nobody has decided
  about.
- A failed control is found again by **rule and resource**.
- **Results need a resource**: `properties.resource`, a logical location or the artifact. Results without one are left
  out and counted. Results of kind `pass` are passed controls, not findings; other kinds (review, informational) are
  left out.
- **Benchmark, control and section** are read from `properties.benchmark`, `properties.control` and
  `properties.section` of the result or its rule, with `security-severity` for the severity, and kept, so findings can be
  filtered by them.
- The **score** is the share of checks that passed, 0 to 100. It comes from the run's `properties.summary`
  (`{ "passed": 47, "failed": 3, "total": 50 }`), or else from the results of kind `pass`. A report with neither has no
  score and adds no point to the trend. Every report that has one adds a point, so the target page draws the trend and
  `/metrics` has `openasy_posture_score{target="..."}`.
- Decisions stay with the finding, on every report: **false positive** (with a reason), **accepted risk** (with a
  reason and an end date) and **compensating control** (another control covers it, with a reason).
- Passwords, tokens and keys in resource names and messages are **masked** before anything is stored.

## Run

```bash
openssl rand -hex 32 > openasy-kek
export POSTURE_INGEST_TOKEN=$(openssl rand -hex 32)
docker compose up -d
docker compose logs posture | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/.

Add a target in the UI, then send a report from CI:

```bash
trivy config --format sarif -o results.sarif .
curl -sf -X POST -H "Authorization: Bearer $POSTURE_INGEST_TOKEN" -H 'content-type: application/json' \
  --data-binary @results.sarif "https://posture.example.com/api/v1/scans?target=prod-cluster" > scan.json
jq -e '.passed' scan.json
```

The body may be gzipped (`Content-Encoding: gzip`), up to 64 MiB unpacked and 50,000 results.

`openasy-kek` encrypts sign-in secrets in posture's database (ADR 0021). Keep it apart from the volume and with your
backups.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `POSTURE_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher. Give every product the same value |
| `POSTURE_INGEST_TOKEN` | | Lets CI send reports and nothing else. An API token with the editor role works too |
| `POSTURE_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `POSTURE_DB` | `/data/posture.db` | SQLite file (WAL), on the `/data` volume |
| `POSTURE_RETENTION_DAYS` | `365` | Reports, and fixed findings nobody decided about, older than this are deleted |
| `POSTURE_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `POSTURE_HEADLESS` | `false` | `true` serves only the API |
| `POSTURE_PASSWORD_SIGN_IN`, `OPENASY_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)) |

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`.

Findings name resources of your infrastructure. Anyone with the viewer role reads them, and deleting a target deletes them.

## Roles

Viewers see everything; editors also decide about findings and send reports; admins also add, change and delete
targets, and manage members and API tokens (ADR 0003).

## Develop

```bash
npm install
npm test        # SARIF parsing, scores, comparison with earlier reports, decisions, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
```

## Licence

AGPL-3.0 (ADR 0008).
