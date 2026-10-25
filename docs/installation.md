# Installation

Kresheen runs as one container (or one Python process) plus a database. Pick one of these ways to install it:

| Way | Good for | Database |
|---|---|---|
| [Desktop app](#desktop-app) | One person on their own computer (Windows, macOS, Linux) | SQLite |
| [Docker Compose](#docker-compose) | A single server, a team, a trial | Bundled PostgreSQL |
| [Helm](#kubernetes-with-helm) | Kubernetes | Bundled PostgreSQL (evaluation) or your own (production) |
| [From PyPI](#from-pypi) | No containers, quick start | SQLite (default) or PostgreSQL |
| [From source](#from-source) | Development | SQLite (default) or PostgreSQL |

Before you start, read [the notes that apply to every install](#notes-for-every-install).

## Desktop app

For one person on their own computer, each release has installers on its [GitHub release page](https://github.com/PeckaCyber/kresheen/releases). They need no Python, Docker or Kubernetes, and Grype is included.

| System | File |
|---|---|
| Windows 10 or 11 (x64) | `kresheen-X.Y.Z-windows-x86_64-setup.exe` (installs for your user, no administrator rights), or the `.zip` |
| macOS 12 or newer (Apple silicon) | `kresheen-X.Y.Z-macos-arm64.dmg` |
| Debian, Ubuntu | `kresheen_X.Y.Z_amd64.deb` (`sudo apt install ./kresheen_X.Y.Z_amd64.deb`) |
| Fedora, RHEL, Rocky | `kresheen-X.Y.Z.x86_64.rpm` (`sudo dnf install ./kresheen-X.Y.Z.x86_64.rpm`) |
| Other Linux (x86_64, glibc 2.28 or newer) | `kresheen-X.Y.Z-linux-x86_64.tar.gz`: unpack it anywhere and run `kresheen` inside |

Start Kresheen from the Start menu, Applications or your desktop's app menu, or run `kresheen` in a terminal. It opens in a window that shows its address; close the window (or press Ctrl+C) to stop it. Your browser opens on its own.

On the first start you create your account: the browser opens a one-time setup link where you choose your email and password. That account is the owner. The link works only on this computer, only once, and only until an account exists.

What the desktop app does differently from a server install:

- It listens on `127.0.0.1` only (port 8765, or a free one if that is taken), so nothing else on the network can reach it. For a shared install, use Compose or Helm.
- Everything is kept in one folder for your user: `%LOCALAPPDATA%\Kresheen` on Windows, `~/Library/Application Support/Kresheen` on macOS, `~/.local/share/kresheen` on Linux (set `KRESHEEN_HOME` to use another). It holds the database, the secret key that encrypts stored tokens (`secret.key`: back it up with the database) and Grype's vulnerability database. Uninstalling the app keeps this folder.
- The installers are not code-signed yet. Windows SmartScreen shows "Windows protected your PC": choose More info, then Run anyway. On macOS, the first time, right-click Kresheen in Applications and choose Open. To check that a download is genuine, [verify it](releases.md#verify-the-desktop-installers) before running it.

The same executable is the full command line too: for example `kresheen create-user --db sqlite:///<data folder>/kresheen.db --email ...` adds an account.

## Docker image

Release images are published as `ghcr.io/peckacyber/kresheen` from version 1.0.0. You can also build the image yourself from a clone of the repository, which is what the Compose file in the repository does:

```bash
docker build -t kresheen:local .
```

The image is small and locked down. It has no shell or package manager, runs as user `65532`, and works with a read-only root filesystem. Only `/data` (the SQLite database, unused with PostgreSQL), `/var/cache/grype` (the vulnerability database cache) and `/tmp` are writable. See [security.md](security.md).

## Docker Compose

You need Docker with Compose v2 and Git.

```bash
git clone https://github.com/PeckaCyber/kresheen.git
cd kresheen
```

### Quick way: the installer

```bash
./install.sh
```

The script asks whether to use Docker Compose or Kubernetes when both are available, shows a preview, and only continues after you confirm. For Compose it:

1. writes a new `KRESHEEN_SECRET_KEY` to `.env` (mode 600) unless one is already there,
2. runs `docker compose up -d`,
3. creates a first owner account, `admin@kresheen.local`, with a random password that is shown once. Change it after signing in.

### By hand

```bash
echo "KRESHEEN_SECRET_KEY=$(openssl rand -base64 32 | tr '+/' '-_')" > .env
docker compose up -d --build
docker compose run --rm app create-user --email you@example.com
```

`create-user` prints a generated password once, unless you pass `--password`. The first account in a deployment is always an owner.

The dashboard is at <http://127.0.0.1:8000>. The Compose file binds it to loopback only. To reach it from other machines, put a TLS-terminating reverse proxy in front and read [security.md](security.md) first.

### Using the published image

The Compose file builds the image from the repository (`build: .`). Once a release image exists (version 1.0.0 or later), to run it instead, replace the `build: .` line of the `app` service with:

```yaml
    image: ghcr.io/peckacyber/kresheen:1.0.0
```

and use `docker compose up -d` without `--build`. To change anything without editing the file, put your changes in a `docker-compose.override.yml`.

### What the Compose file sets up

- `postgres`: PostgreSQL 18 with a volume, not published to the host. Its throwaway credentials suit a local install only.
- `app`: Kresheen, on `127.0.0.1:8000`, with a read-only root filesystem, a tmpfs `/tmp`, all capabilities dropped, a 2 GB memory limit and a volume for the Grype cache.
- `KRESHEEN_AUTO_MIGRATE=1`, so the container upgrades the database schema itself on start.
- `KRESHEEN_SECRET_KEY` from your `.env` file.

### Day to day

```bash
./kresheen-ctl status     # docker compose ps
./kresheen-ctl logs       # follow logs
./kresheen-ctl stop       # stop without removing data
./kresheen-ctl start
```

To update a Compose install that builds locally, take a backup (see [upgrading.md](upgrading.md)), then:

```bash
git pull
docker compose up -d --build
```

With the published image, change the tag in the Compose file and run `docker compose pull && docker compose up -d`.

## Kubernetes with Helm

The chart is in `deploy/helm/kresheen/` in the repository. You need Helm 3 and a cluster whose CNI enforces `NetworkPolicy` if you keep `networkPolicy.enabled` on (the default).

By default the chart runs the published image `ghcr.io/peckacyber/kresheen` at the chart's own version, so chart 1.0.0 runs image 1.0.0. To run an image you built locally, set the repository and tag:

```bash
--set image.repository=kresheen --set image.tag=dev
```

### Evaluation: bundled PostgreSQL

```bash
helm install kresheen deploy/helm/kresheen
```

This starts a single PostgreSQL pod next to the app. It has no replication, no backups and no tuning, and its password is the default in `values.yaml`. Use it to try Kresheen, not to keep data. With the bundled database there is no migration Job, and the app pod upgrades the schema itself on start.

### Production: external PostgreSQL

Create a database and a user, then:

```bash
helm install kresheen deploy/helm/kresheen \
  --set postgresql.enabled=false \
  --set postgresql.externalDatabaseUrl='postgresql+psycopg://USER:PASSWORD@HOST:5432/kresheen'
```

Put the URL in a values file kept out of version control rather than on a shell command line. The chart stores it in a Kubernetes `Secret`.

With an external database:

- A **migration Job** runs `kresheen db upgrade` before each install and upgrade (a Helm `pre-install,pre-upgrade` hook, using the same image). The app pods run with `KRESHEEN_AUTO_MIGRATE=0`, so they never race to migrate, and they refuse to start on an out-of-date schema. If the Job fails, the release fails and the old pods keep running. Read the Job's logs.
- Take a `pg_dump` before every upgrade. Kresheen does not back up PostgreSQL, and migrations only go forward. See [upgrading.md](upgrading.md).

### First user and access

After install the chart prints instructions. In short:

```bash
kubectl exec -it deploy/kresheen -- kresheen create-user --email you@example.com
kubectl port-forward svc/kresheen 8000:8000
```

Then open <http://localhost:8000/>. For real access, enable the ingress:

```yaml
ingress:
  enabled: true
  className: nginx
  host: kresheen.example.com
  tls:
    - secretName: kresheen-tls
      hosts: [kresheen.example.com]
```

### Values worth knowing

| Value | Default | Meaning |
|---|---|---|
| `image.repository`, `image.tag`, `image.pullPolicy` | `ghcr.io/peckacyber/kresheen`, empty (the chart `appVersion`), `IfNotPresent` | Which image to run |
| `image.digest` | empty | Pin the image by digest, for example `sha256:0123...`. When set, the chart runs `repository@digest` and ignores `tag`. |
| `replicaCount` | `1` | Keep at 1. The sign-in throttle lives in each process's memory. The chart refuses a higher number unless `allowMultipleReplicas` is `true`, and accepting that weakens the throttle by the number of replicas. |
| `secretKey` | empty | The Fernet key behind `KRESHEEN_SECRET_KEY`. Empty means the chart generates one on first install and keeps it across upgrades. Back it up. |
| `postgresql.enabled` | `true` | Bundled PostgreSQL (evaluation only) |
| `postgresql.externalDatabaseUrl` | empty | Used when `postgresql.enabled` is `false` |
| `migrations.timeoutSeconds` | `600` | Time limit for the migration Job |
| `grypeCache.sizeLimit` | `3Gi` | Size of the `emptyDir` for the Grype database. It is downloaded again whenever the pod restarts. For a persistent or air-gapped cache, mount a volume at `/var/cache/grype`. |
| `resources` | 100m/128Mi requests, 500m/2Gi limits | Resource requests and limits |
| `serviceAccount.automountToken` | `false` | The app does not call the Kubernetes API |
| `ingress.*` | disabled | `enabled`, `className`, `host`, `annotations`, `tls` |
| `forwardedAllowIps` | empty | Sets `KRESHEEN_FORWARDED_ALLOW_IPS`: the proxy addresses or CIDR ranges (or `*`) whose `X-Forwarded-*` headers are trusted. Set it when you use an ingress. See below. |
| `cookieSecure` | `auto` | Sets `KRESHEEN_COOKIE_SECURE` (`auto`, `always` or `never`). |
| `extraEnv` | `[]` | Extra environment variables for the app and the migration Job, as a normal Kubernetes `env` list (`name` with `value` or `valueFrom`). |
| `networkPolicy.databaseCidrs`, `networkPolicy.databasePort` | `[]`, `5432` | Address ranges and port of an external database that the network policy should allow. |

### Behind an ingress

The app sees the ingress controller's pod address, not the real client, and sees plain HTTP. Without help, the session cookie is not marked `Secure`, HSTS is not sent, and every client looks like the same address in the sign-in throttle and the audit log. Set `forwardedAllowIps` to the range your ingress controller's pods use:

```yaml
ingress:
  enabled: true
  host: kresheen.example.com
  tls:
    - secretName: kresheen-tls
      hosts: [kresheen.example.com]
forwardedAllowIps: "10.42.0.0/16"   # your ingress controller's pod range
cookieSecure: always                 # optional: the site is only served over HTTPS
networkPolicy:
  ingressFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
```

`forwardedAllowIps: "*"` is easier because pod addresses change, but it trusts the forwarded headers from anything that can reach the pod, so a client could fake its address. If you use `*`, keep the network policy on and allow only your ingress controller in `networkPolicy.ingressFrom`. If you leave `forwardedAllowIps` empty, `cookieSecure: always` still gives you a `Secure` cookie, but client addresses stay wrong.

Any other setting from [configuration.md](configuration.md) that the chart has no value for can go in `extraEnv`:

```yaml
extraEnv:
  - name: KRESHEEN_OIDC_ISSUER
    value: https://idp.example.com
  - name: KRESHEEN_OIDC_CLIENT_SECRET
    valueFrom:
      secretKeyRef: {name: kresheen-oidc, key: client-secret}
```

### Network policy

`networkPolicy.enabled` is `true` by default. It applies to the app and migration pods:

- **Ingress**: port 8000, from pods in the same namespace plus anything you list in `networkPolicy.ingressFrom`. Add your ingress controller's namespace there, or the ingress cannot reach the app:

  ```yaml
  networkPolicy:
    ingressFrom:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ingress-nginx
  ```

- **Egress**: DNS, the bundled PostgreSQL if enabled, and HTTPS (port 443) to `networkPolicy.egressCidrs`. The default is `["0.0.0.0/0"]`. Narrow it to the addresses you need: GitHub if you scan repositories, the Grype database host on first use, and `api.anthropic.com` if you turn on AI assist. With an external database (`postgresql.enabled=false`), list its address range in `networkPolicy.databaseCidrs` (for example `["10.0.5.0/24"]`) and its port in `networkPolicy.databasePort` (default `5432`). The rule covers the app and the migration Job. Leave `databaseCidrs` empty if the database is inside the cluster and you allow it with your own policy.

Set `networkPolicy.enabled=false` if your cluster does not enforce `NetworkPolicy` or you manage policy elsewhere.

## From PyPI

From version 1.0.0, Kresheen is also published on PyPI with the web interface included. You need Python 3.11 or newer (3.13 is what the image uses).

```bash
python3 -m venv kresheen-venv
. kresheen-venv/bin/activate
pip install kresheen

kresheen create-user --email you@example.com
kresheen serve --port 8000
```

This uses SQLite in `kresheen.db` in the current directory. The [notes for every install](#notes-for-every-install) apply, and for repository scans install [Grype](https://github.com/anchore/grype) as described under [From source](#from-source).

## From source

You need Python 3.13 (the image uses 3.13; the package declares 3.11 or newer) and Node.js 24 or newer.

```bash
git clone https://github.com/PeckaCyber/kresheen.git
cd kresheen

python3.13 -m venv .venv
. .venv/bin/activate
pip install -e .

cd frontend
npm ci
npm run build          # writes frontend/dist
cd ..

kresheen create-user --email you@example.com
kresheen serve --port 8000
```

`kresheen serve` serves the API and the built web interface from one process, on `127.0.0.1` by default, and stores data in `kresheen.db` in the current directory. Use `--db` or `KRESHEEN_DB_URL` for another database, for example `postgresql+psycopg://user:pass@host:5432/kresheen`. If the web build is not in `frontend/dist` next to the source, pass `--frontend-dist` or set `KRESHEEN_FRONTEND_DIST`.

For repository scans to find vulnerabilities, install [Grype](https://github.com/anchore/grype) and make sure `grype` is on the `PATH`. Without it, repository scans still run but report that the vulnerability scan did not run.

For development, install the test tools with `pip install -e ".[dev]"`, run the backend tests with `pytest`, and use `npm run dev` in `frontend/` for the web interface with hot reload.

## Notes for every install

- **`KRESHEEN_SECRET_KEY`.** A Fernet key. It encrypts the Anthropic API keys people store for AI assist. Without it, the app runs but refuses to store a key. Generate one with `openssl rand -base64 32 | tr '+/' '-_'` or `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Keep a copy somewhere safe: if you lose it, stored keys cannot be read.
- **One process.** Run one worker process. The sign-in throttle is in memory, so extra workers each keep their own counts. The app refuses to start when `WEB_CONCURRENCY` or similar asks for more than one worker unless you set `KRESHEEN_ALLOW_MULTI_WORKER=1`.
- **TLS.** The app speaks plain HTTP. Put a TLS-terminating proxy in front for anything beyond your own machine. See [security.md](security.md).
- **Outbound access.** Repository scans download from `api.github.com`. Grype downloads its vulnerability database (over 1 GB) on first use, so the container needs outbound access once. For an air-gapped install, fill the `/var/cache/grype` volume from another machine first. AI assist, if enabled, calls `api.anthropic.com`.
- **Health check.** `GET /healthz` returns `{"status":"ok"}` without signing in. The image's `HEALTHCHECK` and the chart's probes use it.
- **Debugging a container without a shell.** Attach a throwaway one: `docker debug <container>`, or `kubectl debug -it <pod> --image=busybox --target=kresheen`. `docker logs` and `kubectl logs` show the app's log.
- **Backups.** See [upgrading.md](upgrading.md) and [security.md](security.md).
