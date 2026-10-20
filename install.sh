#!/usr/bin/env bash
# Kresheen installer.
#
# Picks a deployment target (Docker Compose or Kubernetes/Helm), generates
# KRESHEEN_SECRET_KEY, brings the stack up, and creates the first dashboard
# user. Nothing is applied to a cluster or started locally without an explicit
# confirmation after a preview (helm --dry-run=server / docker compose config).
# For Compose the key is written to .env (chmod 600, git-ignored); the Helm
# chart generates its own and keeps it across upgrades.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$REPO_ROOT/.env"
CHART_DIR="$REPO_ROOT/deploy/helm/kresheen"

TARGET=""
ADMIN_EMAIL=""
ADMIN_PASSWORD=""

log()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

confirm() {  # confirm "question" [Y|N]
  local prompt="$1" default="${2:-N}" reply hint="y/N"
  [[ "$default" == "Y" ]] && hint="Y/n"
  read -r -p "$prompt [$hint] " reply || true
  reply="${reply:-$default}"
  [[ "$reply" =~ ^[Yy]$ ]]
}

random_secret() {
  openssl rand -hex 24 2>/dev/null \
    || head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 48
}

# ---- target detection -------------------------------------------------------

detect_target() {
  local has_k8s=0 has_compose=0
  if have kubectl && have helm && kubectl cluster-info >/dev/null 2>&1; then
    has_k8s=1
  fi
  if have docker && docker compose version >/dev/null 2>&1; then
    has_compose=1
  fi

  if (( has_k8s )) && (( has_compose )); then
    log "Both a reachable Kubernetes cluster and Docker Compose are available."
    read -r -p "Install to (k8s/compose)? " TARGET
  elif (( has_k8s )); then
    TARGET=k8s
  elif (( has_compose )); then
    TARGET=compose
  else
    die "Neither a reachable Kubernetes cluster (kubectl+helm) nor Docker Compose was found."
  fi
  [[ "$TARGET" == "k8s" || "$TARGET" == "compose" ]] || die "Target must be k8s or compose."
  log "Target: $TARGET"
}

fernet_key() {  # url-safe base64 of 32 random bytes, the format Fernet requires
  openssl rand -base64 32 2>/dev/null | tr '+/' '-_' \
    || head -c 32 /dev/urandom | base64 | tr '+/' '-_'
}

# ---- k8s apply ---------------------------------------------------------------

apply_k8s() {
  have helm || die "helm not found."
  have kubectl || die "kubectl not found."

  log "Preview (dry-run against the real cluster API -- nothing is created):"
  helm template kresheen "$CHART_DIR" | kubectl apply --dry-run=server -f -

  if ! confirm "Apply this to the cluster now?" N; then
    log "Not applying anything. Re-run install.sh when you're ready."
    return
  fi
  helm upgrade --install kresheen "$CHART_DIR"
  log "Applied. See the NOTES.txt output above for how to reach the dashboard and create the first user."
}

# ---- compose apply -------------------------------------------------------------

# Writes KRESHEEN_SECRET_KEY to .env unless one is already there. Never
# regenerates an existing key: it encrypts stored credentials, so replacing it
# would make them unreadable.
ensure_secret_key() {
  if [[ -f "$ENV_FILE" ]] && grep -q '^KRESHEEN_SECRET_KEY=.\+' "$ENV_FILE"; then
    log "KRESHEEN_SECRET_KEY already set in $ENV_FILE -- leaving it as-is."
    return
  fi
  (
    umask 077
    printf 'KRESHEEN_SECRET_KEY=%s\n' "$(fernet_key)" >> "$ENV_FILE"
  )
  chmod 600 "$ENV_FILE"
  log "Wrote KRESHEEN_SECRET_KEY to $ENV_FILE (mode 600, git-ignored). Back it up."
}

apply_compose() {
  have docker || die "docker not found."

  log "Preview (docker compose config -- nothing started yet):"
  (cd "$REPO_ROOT" && docker compose config >/dev/null) && echo "ok"

  if ! confirm "Bring the stack up now?" N; then
    log "Not starting anything. Re-run install.sh when you're ready."
    return
  fi

  ensure_secret_key
  (cd "$REPO_ROOT" && docker compose up -d)

  # `create-user` errors on a duplicate email rather than replacing the
  # existing account -- re-running install.sh is a no-op here once the first
  # (owner) account exists.
  local password create_out
  password="$(random_secret)"
  log "Creating the first dashboard user (a no-op if one already exists)..."
  create_out="$(mktemp)"
  if (cd "$REPO_ROOT" && docker compose run --rm app create-user --email admin@kresheen.local \
      --password "$password" >"$create_out" 2>&1); then
    ADMIN_EMAIL="admin@kresheen.local"
    ADMIN_PASSWORD="$password"
  else
    log "A dashboard user already exists -- leaving the existing login as-is."
  fi
  rm -f "$create_out"
}

main() {
  detect_target

  case "$TARGET" in
    k8s) apply_k8s ;;
    compose) apply_compose ;;
  esac

  if [[ -n "$ADMIN_PASSWORD" ]]; then
    log "Dashboard login (shown once, change it after signing in):"
    echo "  email:    $ADMIN_EMAIL"
    echo "  password: $ADMIN_PASSWORD"
  fi
  if [[ "$TARGET" == "compose" ]]; then
    log "Dashboard: http://127.0.0.1:8000"
    echo "Day-to-day operation:"
    echo "  ./kresheen-ctl status|start|stop|restart|logs|update"
  fi
}

main "$@"
