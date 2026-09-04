# Bento proving farm — runbook

Self-hosted RISC Zero proving cluster with a Bonsai-compatible REST API. `zkq-prove` talks to it
via `BONSAI_API_URL`; one proof's segments are spread over every prove agent. Hosts and creds come
from `config/deploy.env` (`scripts/lib/config.sh`); every script honours `DRY_RUN=1`.

```
 client (zkq-prove)                 BENTO_INFRA_HOST
 BONSAI_API_URL ──REST──> rest_api :8081
                              │ taskdb            docker scripts/bento/infra-compose.yml
                              ├── postgres :5432 ─┐
                              ├── redis    :6379  ├── native agents: aux exec join snark prove(GPU0..n)
                              └── minio    :9000 ─┘   logs $BENTO_LOG_DIR/*.log, pids $BENTO_LOG_DIR/pids
                                     ▲ DATABASE_URL / REDIS_URL / S3_URL
                        remote GPU boxes: prove(GPU0..n)  <- start_gpu_worker.sh
```

Flow: `exec` cuts segments → `prove` (GPU, any box) → `join` folds STARKs → finalize/resolve
(aux stream) → `snark` wraps to Groth16. Ports 5432/6379/9000 carry dev credentials: reachable
from the farm LAN only.

## 1. Build bento at the SAME risc0 as `Cargo.lock` (version lock)

```bash
grep -A1 'name = "risc0-zkvm"' Cargo.lock          # 3.0.4 — bento must embed exactly this
git clone https://github.com/boundless-xyz/boundless && cd boundless/bento
grep -A1 'name = "risc0-zkvm"' Cargo.lock           # same version, else checkout a matching tag
cargo build --release -p workflow -p api --features workflow/cuda   # -> target/release/{agent,rest_api}
rzup install risc0-groth16                          # groth16 keys: snark agent AND every prove box
```
Needs CUDA ≥ 12.4, `clang libclang-dev protobuf-compiler`. Point `BENTO_AGENT` / `BENTO_REST_API`
in `config/deploy.env` at the binaries.

## 2. Server (infra host)

```bash
scripts/bento/start_server.sh   # docker infra, wait healthy, rest_api, aux/exec/join/snark, 1 prove per GPU
scripts/bento/status.sh         # health, agents, GPUs, taskdb counts, VERSION LOCK (exit 1 on mismatch)
scripts/bento/stop.sh           # kill agents + rest_api; KEEP_INFRA=0 also tears down docker infra
```

## 3. GPU workers (any box with an NVIDIA driver, no build needed)

```bash
scp $BENTO_AGENT root@<box>:/root/bento/agent      # links only libcuda.so.1
ssh root@<box> rzup install risc0-groth16
BENTO_AGENT=/root/bento/agent scripts/bento/start_gpu_worker.sh          # all GPUs; GPUS=0,2 to select
```
Workers join immediately, even into a proof in flight.

## 4. Prove

```bash
RISC0_DEV_MODE=0 BONSAI_API_URL=http://<infra-host>:8081 BONSAI_API_KEY=anything \
  target/release/zkq-prove --fixture fixtures/quorum_ok.bin --mode groth16 --out proof.json
target/release/zkq-prove verify --proof proof.json
```

## 5. Sizing (this guest, `SEGMENT_PO2=20`, RTX 4090 Laptop)

| item | value |
|---|---|
| guest cycles | ~215 M → ~210 segments |
| prove | ~210 × 3 s ≈ 640 GPU-s |
| join | ~210 × 1.5 s ≈ 320 GPU-s |
| Groth16 wrap | 30–40 s, one task |
| wall | ≈ 960 / N_GPU + 60 s; measured ~5 min on 4 GPUs |
| VRAM per prove agent | po2 20: 3–5 GB; po2 21: ~9 GB |

## 6. Troubleshooting

| symptom | cause / fix |
|---|---|
| `control_id mismatch`, `verify lift: proof is invalid` | agent risc0 ≠ client. `status.sh`; rebuild bento at the Cargo.lock version; never `cargo update`. |
| tasks pile up `ready`, GPUs idle | no `aux` agent. Restart via `start_server.sh`. |
| jobs stay `running` after the client died | `scripts/bento/cancel_job.sh <job_id>` or `cancel_job.sh all-stale`. |
| `Missing required risc0-groth16 rzup component` | a prove box without groth16 keys drew the wrap: `rzup install risc0-groth16` everywhere. |
| prove agent OOM / CUDA error | free VRAM (`start_gpu_worker.sh` warns < 6 GB) or lower `SEGMENT_PO2`. |
| `rest_api` unreachable | `$BENTO_LOG_DIR/rest_api.log`; `docker compose -f scripts/bento/infra-compose.yml ps`. |
| worker cannot connect | ports 5432/6379/9000 on the infra host blocked. |

Alternative (untested): fully containerised stack, `docker/README.md`.
