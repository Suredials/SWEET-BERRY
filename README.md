# SweetBerry / Defense Grid 0.4

Adaptive deception laboratory on a Raspberry Pi. Functional Samba AD, Linux,
Gitea and AWS-compatible APIs feed an evidence index and a local SOC dashboard.
A guarded corporate chatbot and a deliberately vulnerable support portal add
AI and application interaction paths.

**LLM proposes. Code decides.** DeepSeek publishes validated investigations and
findings. It has no shell, Docker, firewall or infrastructure-control capability.
Detection, evidence collection and replay do not depend on the model.

## Addresses and services

Management: **172.27.66.1**, administrative SSH 22 and
**[SOC dashboard](http://172.27.66.1:8501)**. The control API binds 127.0.0.1:8000.

| Public target | Service | Functional behavior |
|---|---|---|
| .10 | Samba DC01 | DNS 53/1053, Kerberos 88, LDAP 389, SMB 445; real lab users, groups, computer objects and shares |
| .20:22 | backup01 through Cowrie | Real unprivileged Linux shell with session recordings |
| .30:8088 | intranet01 | Employee directory and real documents |
| .40:3000 | git01 | Gitea organization, repository, issues, clones and adaptive commits |
| .50:4566 | cloud01 | Moto S3, read-only IAM and STS API operations |
| .50:9080 | Cloud compatibility facade | Existing lab object routes backed by Moto |
| .60 | OpenCanary | FTP 2121, MSSQL 1433, MySQL 3306, RDP 3389, Redis 6379 and MongoDB 27017 facades |
| .70:80 | assistant01 | Corporate chatbot with real Protect AI LLM Guard scanners |
| .80:80 | support01 | Deliberately unrestricted executable-file upload, inside an unprivileged container |

All public addresses above use the 172.27.66.0/24 lab network. There are fourteen
containers, including independent HTTP evidence gateways, Cowrie, LLM Guard and
a private DNS sink. They share the Pi kernel; these are not separate VMs.
The shared `infra/company.json` supplies corporate identities to AD, portal and bot.

Internal target endpoints for the support container's permitted pivot:

- Git: `http://172.30.67.42:8080/northstar/backup-scripts.git`
- AWS APIs: `http://172.30.67.50:8080`

These are documented in `/srv/corp/operations.txt` inside support01. Public Wi-Fi
aliases are external entrypoints; use the private endpoints from inside the target.

## Start, reset and offline operation

Verified deployment: Kali ARM64 on Raspberry Pi, 8 GB RAM, Python 3.14.7,
Docker Engine 28.5.2 and Compose 2.40.3. Core Python dependencies support 3.11+.
LLM Guard runs separately under Python 3.12. The network scripts assume the
existing `wlan0` / `kali-mgmt-ap` profile with management address .1.

Prerequisites: Docker Compose v2, Tshark, strace, Suricata, tcpdump and system
Python PyYAML. From `/home/suredials/sweetberry`:

```sh
sh run.sh
sh smoke.sh
```

The launcher uses existing images. To rebuild infrastructure changes:

```sh
SWEETBERRY_BUILD=true sh run.sh
```

The first LLM Guard setup downloads public model weights once. Its external
`sweetberry_guard-cache` volume survives lab resets. Subsequent starts can load
the guard offline. No AWS account or AWS production credentials are required.

```sh
sh reset_demo.sh
```

Reset stops project collectors, archives evidence under `runtime/archive/`,
recreates target volumes and seeds initial AD, Gitea and Moto state. It preserves
management keys, .env credentials and the external guard model cache. Previously
exposed adaptive documents and cloud canaries start hidden again. Reset is
restricted to the verified deployment directory.

Offline UI/replay on this Windows machine: `./run.ps1`. On Linux:
`SWEETBERRY_OFFLINE=true sh run.sh`. Neither requires Docker or a model provider.

Systemd units:

- `sweetberry-infra`: guarded containers and idempotent fixture initialization.
- `sweetberry-api`: sensors, evidence index, correlation and SOC N2 worker.
- `sweetberry-dashboard`: browser UI and limited server-side admin proxy.
- `sweetberry-chat-broker`: private guarded inference; provider keys stay here.
- `sweetberry-network-sensor`: project-scoped passive Suricata IDS.
- `sweetberry-pcap`: bounded circular packet capture.

## Evidence and correlation

Three layers complement one another:

1. Network: Suricata alerts, flows, DNS, HTTP, TLS metadata, SSH/SMB metadata,
   file metadata and capture statistics. Full packets are retained in a bounded ring.
2. Host: strace attaches target processes and descendants, observing execution,
   redacted arguments, process ancestry, file opens, renames/deletions and sockets.
3. Application: independent HTTP gateways, Cowrie, Samba audit, chatbot broker,
   DNS sink and container output record request/session-specific evidence.

`runtime/telemetry/evidence-*.jsonl` contains structured evidence segments.
`index.sqlite` is a SQLite WAL query index. Each observation has a stable ID and
raw segment/offset reference. Late-arriving evidence is correlated asynchronously.
The index retains the original observed source when adding a derived source.

- SSH uses Cowrie's backend socket tuple and host process ancestry.
- Web uses the independent gateway request ID, PHP runtime interval and process ancestry.
- Cross-service pivots additionally use the process socket's local tuple and the
  receiving gateway's client port, when those observations exist.
- Missing evidence stays unattributed. A shared IP or close timestamps alone do
  not establish that two interactions have the same operator.

The observer includes the host boot ID in process identities, translates PID namespaces and joins unfinished/resumed syscall
records. Some records represent attempts and others completion; their phase and
result remain available. Short processes that finish before attachment can be
missed. This is not exhaustive EDR or a guarantee of visibility into every action.
Encrypted contents require application/session logs; packet capture does not decrypt them.

Default retention:

- Evidence segments: approximately 4 GiB in 64 MiB rotations; index entries expose
  whether their raw segment still exists.
- PCAP: eight 128 MB rotating files, approximately 1 GB total.
- HTTP bodies: first 64 KiB, with truncation indicated; uploads up to 5 MiB are
  hashed and quarantined separately, with a 256 MiB sample budget.
- Container stdout: four 16 MB files per container. Gateway logs also rotate.

Administration, model-provider traffic and the private inference path are excluded
from packet capture. Raw evidence stays local. In live mode, selected sanitized
context is sent to Primalabs.

## SOC dashboard

- Overview: risk, techniques, canaries, adaptive mutations and eight target nodes.
- Operator style: human-like, automation-like, agent-compatible or insufficient
  evidence, with signals and heuristic support. Speed or a user-agent string is
  not proof of AI control. Scripts can reproduce agent-compatible behavior.
- Event explorer and attack paths: canonical detections and deterministic responses.
- Telemetry & tracing: source/asset/kind/request/process/canary filters, stable
  pagination, process relationships, evidence references and JSON export.
- Routine file reads remain indexed. Toggle their display when investigating noise.
- Intelligence: observed IPs, DNS names, hashes and canaries, with evidence-linked
  SOC findings and CSV export. No invented actor attribution or external reputation.
- AI defense: messages, scanner decisions, tool reads and model responses.
- SOC N2: source-specific investigations, revision history, findings and reports.
- Coverage: sensor state, reader errors, packet-drop statistics, retention and limits.

## Chatbot and model boundaries

Protect AI LLM Guard 0.3.16 uses BanSubstrings, Secrets and the public
`protectai/deberta-v3-base-prompt-injection-v2` classifier. Input and output
checks are recorded. An unavailable required guard prevents model calls; the
chatbot responds using a clearly identified local fallback.

The broker chooses one predefined employee/document lookup per turn. No arbitrary
paths, URLs, shell commands or SQL are available to the chatbot. The public
container has a private broker token, not the Primalabs or collector credentials.
Model output is rendered as text. Per-source rate limits and serialized model
calls bound provider usage.

SOC N2 independently receives canonical actions, normalized process families,
selected indicator metadata and evidence references. Raw prompts, commands,
passwords, arbitrary bodies and executable names are excluded. It publishes only
schema-validated reports and findings. Operator assessments require adequate
independent evidence and are capped at heuristic confidence; no claim of certain
human or AI identity is permitted.

Private `.env`, mode 600:

```dotenv
LLM_MODE=live
LLM_PROVIDER=primalabs
LLM_MODEL=primalabs-ai/DeepSeek-V4.1-Flash-1017
PRIMALABS_API_KEY=<private key>
```

Use `LLM_MODE=mock` for deterministic SOC reports without provider calls. Restart
the API and chat broker after changing provider configuration. The existing
`ops/configure-provider.py` prompts securely and writes the remote .env via SFTP.

## Controlled vulnerable target and AWS lab

The support portal deliberately accepts executable PHP attachments and serves
them under `/uploads/`. A successful request can run code as UID 10001 inside
that container. Its independent gateway and host collector preserve evidence
outside the target's filesystem. No exploit payload or malware is automatically run.

Containment: no Docker socket or host directories mounted into support01; read-only
root filesystem; 64 MiB /tmp; 16 PIDs; 0.75 CPU; inherited 128 MiB virtual-address
space per process; 10 MiB maximum per file. A host watchdog stops the target if
upload storage exceeds 128 MiB or 256 files. This kernel lacks memory cgroups,
so configured Docker memory limits are not enforced; the per-process limit is a
separate control, not a container RAM quota.

New target connections are restricted to the Git/cloud gateways and local DNS.
Unknown DNS names receive NXDOMAIN and are logged, without Internet forwarding.
Administrative access and other LAN/Internet destinations are rejected. The Pi's
own Internet access remains available to its private model broker.

Moto exposes emulated S3/IAM/STS operations. The external gateway permits read
operations and rejects modification/reset operations. The synthetic backup
bucket deliberately allows anonymous object reads to retain the original lab
facade. IAM objects are descriptive fixtures; this is not full IAM enforcement.
All example keys and canaries include SWEETBERRY_CANARY_DECOY and are inert.

AD CS, cracking, malware and active AS-REP probing are not implemented. Normal
Kerberos authentication remains enabled. The replay AS-REP storyline is synthetic.

## Demonstrations and verification

Optional clients: `python -m pip install -r requirements-demo.txt`.

```sh
python scripts/live_ad.py
python scripts/live_devops.py
python scripts/live_linux.py
python scripts/check_protocols.py
python scripts/check_observer.py
python scripts/check_sessions.py
python scripts/check_full_chain.py
```

`check_full_chain.py` uploads a controlled PHP fixture containing fixed harmless
commands: identity inspection and Git/cloud reads. It verifies the upload hash,
unprivileged execution, forged-header replacement and request/process/socket
correlation. It never runs the uploaded file on the administration host.

Linux lab login: `analyst / SWEETBERRY_CANARY_DECOY_LabOnly!`:

```sh
ssh analyst@172.27.66.20
```

Deterministic replay scenarios do not execute target actions or send fixtures to
DeepSeek. Existing scenarios remain available through the Replay lab or:

```sh
python scripts/replay.py scenarios/replay_full_attack.json
```

```sh
python -m pytest -q
sh smoke.sh
sudo docker compose ps --all
sudo journalctl -u sweetberry-api -n 30
```

Browser QA on the Windows administration machine uses installed Chrome:
`python scripts/check_soc.py`. Screenshots are saved under `runtime/previews/`.

## Upstream components

[Samba](https://www.samba.org/), [Cowrie](https://github.com/cowrie/cowrie),
[OpenCanary](https://github.com/thinkst/opencanary),
[Gitea](https://docs.gitea.com/), [Moto](https://docs.getmoto.org/),
[LLM Guard](https://github.com/protectai/llm-guard),
[Suricata](https://docs.suricata.io/), [strace](https://strace.io/) and
[MITRE ATT&CK](https://attack.mitre.org/).
