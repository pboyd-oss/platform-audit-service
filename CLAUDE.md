# platform-audit-service

Security event correlation for build pipeline activity. Correlates Tetragon exec events, MITM proxy HTTP events, and pipeline step graphs to produce per-build audit summaries used as Cedar policy input.

## Local deploy (bypassing Jenkins)

The `platform` namespace has a Kyverno `require-signed-platform-images` policy (Enforce mode) that blocks unsigned images. Manually pushed images need to be cosign-signed before deployment.

**Build and sign workflow:**

```bash
# Extract cosign key (password is empty — the pipeline uses COSIGN_PASSWORD="")
kubectl get secret cosign-key -n jenkins -o jsonpath='{.data.cosign\.key}' | base64 -d > /tmp/cosign.key

# Build for linux/amd64 (cluster arch — easy to forget on Apple Silicon)
docker build --platform linux/amd64 --no-cache -t harbor.tuxgrid.com/platform/audit-service:latest .
docker push harbor.tuxgrid.com/platform/audit-service:latest
# Note the digest from the push output

# Sign with cosign (disable tlog and new bundle format so signature lands as .sig tag)
DIGEST=sha256:<from push output>
COSIGN_PASSWORD="" cosign sign \
  --key /tmp/cosign.key \
  --tlog-upload=false \
  --use-signing-config=false \
  --new-bundle-format=false \
  --yes \
  harbor.tuxgrid.com/platform/audit-service@${DIGEST}

# Deploy using the explicit digest (not :latest — Kyverno caches tag resolution
# and will keep pinning :latest to the old signed digest from Jenkins)
kubectl set image deployment/platform-audit-service -n platform \
  audit-service=harbor.tuxgrid.com/platform/audit-service@${DIGEST}
kubectl rollout status deployment/platform-audit-service -n platform
```

**Why not just `kubectl rollout restart`?** Kyverno has `useCache:true` on the `latest` tag — it pins to the last signed digest it resolved and won't re-resolve until the cache expires. Using an explicit digest sidesteps the cache entirely.

## Endpoints

Listens on `:8080`. Auth controlled by `INGEST_SECRET` env var.

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Health check |
| `POST` | `/ingest/event` | Pipeline step event (BUILD_START, STEP_START, STEP_END, BUILD_END) |
| `POST` | `/ingest/tetragon` | Tetragon kernel exec/network event |
| `POST` | `/ingest/http` | MITM proxy HTTP request event |
| `GET` | `/builds/` | Build list (JSON) |
| `GET` | `/builds/{auditId}/summary` | Correlated audit summary for a build |
| `GET` | `/ui` | Web UI (embedded) |

## Web UI

`http://audit.tuxgrid.com/ui` — gateway-internal, no Cloudflare. Shows build list with step trees, exec correlation, and HTTP request log per build.

## Data

Stored in `/data/builds/{auditId}/`:
- `events.ndjson` — pipeline step events
- `tetragon.ndjson` — kernel exec events
- `http.ndjson` — MITM proxy HTTP events
- `correlated.json` — final correlation report (written after BUILD_END)

## AuditId format

`{job_path_underscored}_{build_number}` — e.g. `teams_team-a_nginx-pipeline_build_25`

Derived identically by:
- `01-audit-graph-listener.groovy`: `run.parent.fullName.replace('/', '_') + '_' + run.number`
- `platform-tetragon-forwarder`: strips last `-` segment from `jenkins/label` pod label
- `mitmproxy hooks.py`: strips last `-` segment from `JENKINS_LABEL` env var (downward API)
