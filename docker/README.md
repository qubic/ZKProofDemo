# docker/

| File | Purpose |
|---|---|
| `Dockerfile.dev` | Ubuntu 24.04 build image: gcc, Rust 1.96.1, rzup (guest rust 1.94.1, cpp 2024.1.5, r0vm 3.0.4), Foundry v1.7.1. Every installer sha256/version pinned. |
| `docker-compose.yml` | `dev` service (repo mounted at `/work`) + profile `bento`: single-box GPU proving stack from official boundless images. |
| `docker-compose.worker.yml` | Prove-only agents for extra GPU boxes pointing at that stack. |
| `bento.env.example` | Tunables/credentials for the compose bento stack. |

All commands run from the project root.

## Dev image

```bash
docker build -f docker/Dockerfile.dev -t zkq-dev .      # ~10 min; rzup rate-limited? add --secret id=github_token,env=GITHUB_TOKEN
docker run --rm -it -v "$PWD:/work" zkq-dev             # or: docker compose -f docker/docker-compose.yml up -d dev && ... exec dev bash
crypto/tests/run_tests.sh                                # inside: C port vs reference
RISC0_DEV_MODE=1 cargo test --release --locked
RISC0_DEV_MODE=1 scripts/demo_quorum_ok.sh
```

`RISC0_DEV_MODE=1` (compose default) emits fake receipts. A real Groth16 seal needs bento
(below or `docs/BENTO.md`); without the `cuda` feature risc0 wraps STARK→Groth16 via
`docker run risczero/risc0-groth16-prover`, which the dev container cannot do.

## Bento GPU stack (compose profile, untested by the authors)

The path proven on the authors' farm is the native agents in `scripts/bento/` (`docs/BENTO.md`).
This profile runs the official `ghcr.io/boundless-xyz/boundless/bento-*` images instead; `BENTO_TAG`
has no default: pin an image that ships risc0-zkvm 3.0.4 (client == agent, else `control_id mismatch`).

Host needs the NVIDIA driver + [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)
(`docker run --rm --runtime=nvidia --gpus all ubuntu:24.04 nvidia-smi` works) and ~8–11 GB VRAM per GPU.

```bash
cp docker/bento.env.example docker/bento.env                              # set BENTO_TAG
docker compose -f docker/docker-compose.yml --env-file docker/bento.env --profile bento up -d
curl -s localhost:8081/health
BENTO_INFRA_HOST=<server-ip> docker compose -f docker/docker-compose.worker.yml up -d   # extra GPU boxes
docker compose -f docker/docker-compose.yml --profile bento down                          # -v drops the task DB
```

Services: postgres (task DB), redis, minio (S3), `rest_api` :8081 (Bonsai-compatible),
`aux_agent` (mandatory: refreshes scheduler counters), `exec_agent`, `join_agent`, `snark_agent`
(Groth16 wrap), `gpu_prove_agent` (one `agent -t prove` per GPU). Ports 5432/6379/9000 carry
dev credentials: reachable from worker boxes only.

Client: `RISC0_DEV_MODE=0 BONSAI_API_URL=http://<host>:8081 BONSAI_API_KEY=anything scripts/demo_quorum_ok.sh`.
