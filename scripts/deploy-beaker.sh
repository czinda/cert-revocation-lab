#!/bin/bash
# ── deploy-beaker.sh ─────────────────────────────────────────────────────
#
# Provision a RHEL system via Red Hat Beaker and deploy the cert-revocation-lab
# with PQC (ML-DSA-87) + Hoike OCSP + Kipuka EST + Akamu ACME.
#
# Prerequisites:
#   - curl with Kerberos/SPNEGO support
#   - VPN connected to Red Hat network
#   - Valid Kerberos ticket (kinit czinda@REDHAT.COM) or will prompt
#   - SSH key configured for Beaker systems (~/.ssh/id_rsa)
#
# Usage:
#   ./scripts/deploy-beaker.sh                    # RHEL 10, PQC, 16 GB RAM
#   ./scripts/deploy-beaker.sh --distro RHEL-10.2 # Specific distro
#   ./scripts/deploy-beaker.sh --pki-mode all     # All 3 PKI hierarchies
#   ./scripts/deploy-beaker.sh --memory 32768     # 32 GB RAM
#   ./scripts/deploy-beaker.sh --skip-provision   # Deploy to existing system
#   ./scripts/deploy-beaker.sh --hostname beaker-host.example.com  # Use existing
#
# Assisted-by: Claude Code (claude.ai/code)
# ─────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────
DISTRO="${DISTRO:-RHEL-10%}"
ARCH="${ARCH:-x86_64}"
MIN_MEMORY="${MIN_MEMORY:-16384}"     # 16 GB
MIN_DISK="${MIN_DISK:-80}"            # 80 GB
PKI_MODE="${PKI_MODE:-pqc}"
REPO_URL="${REPO_URL:-https://github.com/czinda/cert-revocation-lab.git}"
REPO_BRANCH="${REPO_BRANCH:-feature/hoike-ocsp-hsm}"
DEPLOY_DIR="${DEPLOY_DIR:-/opt/cert-revocation-lab}"
RESERVE_DURATION="${RESERVE_DURATION:-172800}"  # 48 hours
SSH_USER="${SSH_USER:-root}"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30"
SKIP_PROVISION=false
BEAKER_HOSTNAME=""
JOB_ID=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_success() { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_phase()   { echo -e "\n${GREEN}══════════════════════════════════════════════${NC}"; echo -e "${GREEN}  $*${NC}"; echo -e "${GREEN}══════════════════════════════════════════════${NC}\n"; }

# ── Parse Arguments ───────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --distro)       DISTRO="$2"; shift 2 ;;
        --arch)         ARCH="$2"; shift 2 ;;
        --memory)       MIN_MEMORY="$2"; shift 2 ;;
        --disk)         MIN_DISK="$2"; shift 2 ;;
        --pki-mode)     PKI_MODE="$2"; shift 2 ;;
        --branch)       REPO_BRANCH="$2"; shift 2 ;;
        --reserve)      RESERVE_DURATION="$2"; shift 2 ;;
        --skip-provision) SKIP_PROVISION=true; shift ;;
        --hostname)     BEAKER_HOSTNAME="$2"; SKIP_PROVISION=true; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --distro NAME      Beaker distro (default: RHEL-10%)"
            echo "  --arch ARCH        Architecture (default: x86_64)"
            echo "  --memory MB        Minimum RAM in MB (default: 16384)"
            echo "  --disk GB          Minimum disk in GB (default: 80)"
            echo "  --pki-mode MODE    PKI mode: rsa|ecc|pqc|dual|all (default: pqc)"
            echo "  --branch BRANCH    Git branch to deploy (default: feature/hoike-ocsp-hsm)"
            echo "  --reserve SECS     Reservation duration (default: 172800 = 48h)"
            echo "  --skip-provision   Skip Beaker provisioning, deploy to existing system"
            echo "  --hostname HOST    Deploy to specific host (implies --skip-provision)"
            echo "  --help             Show this help"
            exit 0
            ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# Map pki-mode to start-lab.sh flags
case "$PKI_MODE" in
    rsa)  PKI_FLAG="--rsa" ;;
    ecc)  PKI_FLAG="--ecc" ;;
    pqc)  PKI_FLAG="--pqc" ;;
    dual) PKI_FLAG="--dual" ;;
    all)  PKI_FLAG="--all" ;;
    *)    log_error "Invalid PKI mode: $PKI_MODE (expected: rsa|ecc|pqc|dual|all)"; exit 1 ;;
esac

# ── Phase 1: Check Prerequisites ─────────────────────────────────────
log_phase "Phase 1: Checking Prerequisites"

BEAKER_URL="${BEAKER_URL:-https://beaker.engineering.redhat.com}"

if ! command -v curl &>/dev/null; then
    log_error "curl not found"
    exit 1
fi
log_success "curl available"

if ! command -v ssh &>/dev/null; then
    log_error "ssh not found"
    exit 1
fi
log_success "ssh available"

# Check Kerberos ticket
if ! klist -s 2>/dev/null; then
    log_warn "No valid Kerberos ticket found"
    log_info "Running kinit..."
    kinit czinda@REDHAT.COM || {
        log_error "kinit failed. Ensure VPN is connected."
        exit 1
    }
fi
log_success "Kerberos ticket valid: $(klist 2>/dev/null | grep 'Default principal' | awk '{print $3}')"

# ── Phase 2: Beaker Provisioning ─────────────────────────────────────
if [ "$SKIP_PROVISION" = true ]; then
    if [ -z "$BEAKER_HOSTNAME" ]; then
        log_error "--skip-provision requires --hostname"
        exit 1
    fi
    log_info "Skipping Beaker provisioning, using: $BEAKER_HOSTNAME"
else
    log_phase "Phase 2: Submitting Beaker Job"

    log_info "Requesting:"
    log_info "  Distro:   $DISTRO"
    log_info "  Arch:     $ARCH"
    log_info "  Memory:   >= ${MIN_MEMORY} MB"
    log_info "  Disk:     >= ${MIN_DISK} GB"
    log_info "  Reserve:  $(( RESERVE_DURATION / 3600 )) hours"
    echo ""

    # Create Beaker job XML
    JOB_XML=$(cat <<'JOBEOF'
<job>
  <whiteboard>cert-revocation-lab PQC deployment</whiteboard>
  <recipeSet>
    <recipe whiteboard="cert-lab-pqc" ks_meta="autopart_type=plain">
      <distroRequires>
        <and>
          <distro_name op="like" value="__DISTRO__"/>
          <distro_arch op="=" value="__ARCH__"/>
        </and>
      </distroRequires>
      <hostRequires>
        <and>
          <memory op=">=" value="__MEMORY__"/>
          <disk>
            <disk_size op=">=" value="__DISK__" units="GB"/>
          </disk>
        </and>
      </hostRequires>
      <repos/>
      <task name="/distribution/reservesys" role="STANDALONE">
        <params>
          <param name="RESERVETIME" value="__RESERVE__"/>
        </params>
      </task>
    </recipe>
  </recipeSet>
</job>
JOBEOF
)

    # Substitute values
    JOB_XML="${JOB_XML//__DISTRO__/$DISTRO}"
    JOB_XML="${JOB_XML//__ARCH__/$ARCH}"
    JOB_XML="${JOB_XML//__MEMORY__/$MIN_MEMORY}"
    JOB_XML="${JOB_XML//__DISK__/$MIN_DISK}"
    JOB_XML="${JOB_XML//__RESERVE__/$RESERVE_DURATION}"

    # Authenticate to Beaker REST API (two-step: SPNEGO → session cookie)
    COOKIE_JAR=$(mktemp /tmp/beaker-cookies-XXXXXX)
    log_info "Authenticating to Beaker REST API..."
    AUTH_RESPONSE=$(curl -sf --negotiate -u : \
        -c "$COOKIE_JAR" \
        "${BEAKER_URL}/bkr-api/login" 2>&1) || true

    if ! echo "$AUTH_RESPONSE" | grep -q "username"; then
        log_error "Beaker authentication failed"
        log_error "Response: $AUTH_RESPONSE"
        rm -f "$COOKIE_JAR"
        exit 1
    fi
    BKR_USER=$(echo "$AUTH_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('username',''))" 2>/dev/null || true)
    log_success "Authenticated as: $BKR_USER"

    # Submit job via REST API
    JOB_XML_JSON=$(echo "$JOB_XML" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
    SUBMIT_RESPONSE=$(curl -sf -b "$COOKIE_JAR" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{\"ignore_missing_tasks\": false, \"xml\": $JOB_XML_JSON}" \
        "${BEAKER_URL}/bkr-api/jobs" 2>&1) || true

    JOB_ID=$(echo "$SUBMIT_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    jid = data.get('id', '')
    print(f'J:{jid}' if jid else '')
except:
    print('')
" 2>/dev/null || true)

    if [ -z "$JOB_ID" ]; then
        log_error "Failed to submit Beaker job"
        log_error "Response: $SUBMIT_RESPONSE"
        rm -f "$COOKIE_JAR"
        exit 1
    fi
    log_success "Job submitted: $JOB_ID"

    # ── Phase 2b: Wait for Provisioning ──────────────────────────────
    log_phase "Phase 2b: Waiting for Beaker System"
    log_info "Polling job status every 60 seconds..."

    elapsed=0
    max_wait=7200  # 2 hours max
    while [ $elapsed -lt $max_wait ]; do
        JOB_NUM="${JOB_ID#J:}"
        JOB_STATUS=$(curl -sf -b "$COOKIE_JAR" \
            "${BEAKER_URL}/bkr-api/jobs/${JOB_NUM}" 2>/dev/null | \
            python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    status = data.get('status', 'Unknown')
    system = ''
    for rs in data.get('recipe_sets', data.get('recipesets', [])):
        for r in rs.get('recipes', rs.get('machine_recipes', [])):
            s = r.get('resource', {}).get('fqdn', r.get('system', ''))
            if s:
                system = s
                break
            status = r.get('status', status)
    print(f'{status}|{system}')
except Exception as e:
    print(f'Unknown|')
" 2>/dev/null || echo "Unknown|")

        STATUS="${JOB_STATUS%%|*}"
        SYSTEM="${JOB_STATUS##*|}"

        case "$STATUS" in
            Reserved|Completed)
                BEAKER_HOSTNAME="$SYSTEM"
                log_success "System reserved: $BEAKER_HOSTNAME"
                break
                ;;
            Running)
                log_info "[$((elapsed/60))m] Status: $STATUS — provisioning in progress..."
                ;;
            Queued|Scheduled|Waiting|New|Processed)
                log_info "[$((elapsed/60))m] Status: $STATUS — waiting for system..."
                ;;
            Cancelled|Aborted)
                log_error "Job $JOB_ID was $STATUS"
                exit 1
                ;;
            *)
                log_info "[$((elapsed/60))m] Status: $STATUS"
                ;;
        esac

        sleep 60
        elapsed=$((elapsed + 60))
    done

    if [ -z "$BEAKER_HOSTNAME" ]; then
        log_error "Timed out waiting for Beaker system after $((max_wait/3600)) hours"
        log_info "Check manually: curl -sf -b $COOKIE_JAR ${BEAKER_URL}/bkr-api/jobs/${JOB_ID#J:}"
        exit 1
    fi
fi

# ── Phase 3: Wait for SSH ─────────────────────────────────────────────
log_phase "Phase 3: Connecting to $BEAKER_HOSTNAME"

log_info "Waiting for SSH to become available..."
ssh_wait=0
while [ $ssh_wait -lt 600 ]; do
    if ssh $SSH_OPTS "$SSH_USER@$BEAKER_HOSTNAME" "echo ready" 2>/dev/null; then
        log_success "SSH connection established"
        break
    fi
    sleep 15
    ssh_wait=$((ssh_wait + 15))
    log_info "Waiting for SSH... (${ssh_wait}s)"
done

if [ $ssh_wait -ge 600 ]; then
    log_error "SSH not available after 10 minutes"
    exit 1
fi

# Show system info
log_info "System information:"
ssh $SSH_OPTS "$SSH_USER@$BEAKER_HOSTNAME" "
    echo '  OS:     ' \$(cat /etc/redhat-release 2>/dev/null || echo unknown)
    echo '  Kernel: ' \$(uname -r)
    echo '  RAM:    ' \$(free -h | awk '/^Mem:/{print \$2}')
    echo '  Disk:   ' \$(df -h / | awk 'NR==2{print \$2}')
    echo '  CPU:    ' \$(nproc) cores
"

# ── Phase 4: Deploy Lab ───────────────────────────────────────────────
log_phase "Phase 4: Deploying cert-revocation-lab"

log_info "Deploying with:"
log_info "  PKI mode:  $PKI_MODE ($PKI_FLAG)"
log_info "  Branch:    $REPO_BRANCH"
log_info "  Deploy to: $DEPLOY_DIR"
echo ""

# Transfer and execute deployment
ssh $SSH_OPTS "$SSH_USER@$BEAKER_HOSTNAME" bash -s -- \
    "$REPO_URL" "$REPO_BRANCH" "$DEPLOY_DIR" "$PKI_FLAG" <<'DEPLOY_SCRIPT'
#!/bin/bash
set -uo pipefail

REPO_URL="$1"
REPO_BRANCH="$2"
DEPLOY_DIR="$3"
PKI_FLAG="$4"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ── 4a: Install packages ──────────────────────────────────────────
log "Installing packages..."
# RHEL 10 uses netavark (not CNI plugins), podman-compose via pip
dnf install -y --setopt=install_weak_deps=False \
    podman buildah skopeo \
    git curl wget jq openssl \
    python3 python3-pip \
    bind-utils openssh-clients \
    gcc openssl-devel pkg-config \
    slirp4netns fuse-overlayfs \
    softhsm opensc 2>/dev/null || true

# podman-compose is not packaged in RHEL 10 base repos
pip3 install --break-system-packages podman-compose typer rich httpx 2>/dev/null || \
    pip3 install podman-compose typer rich httpx 2>/dev/null || true

# ── 4b: Install Rust toolchain (for hoike build) ──────────────────
if ! command -v cargo &>/dev/null; then
    log "Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable --profile minimal
    source "$HOME/.cargo/env"
fi
log "Rust: $(rustc --version 2>/dev/null || echo 'not available')"

# ── 4c: Kernel tuning ────────────────────────────────────────────
sysctl -w fs.inotify.max_user_watches=524288 2>/dev/null || true
sysctl -w fs.inotify.max_user_instances=512 2>/dev/null || true

# ── 4d: Clone repo ───────────────────────────────────────────────
log "Cloning repository..."
if [ -d "$DEPLOY_DIR" ]; then
    cd "$DEPLOY_DIR"
    git fetch --all
    git checkout "$REPO_BRANCH"
    git pull origin "$REPO_BRANCH" || true
else
    git clone --branch "$REPO_BRANCH" "$REPO_URL" "$DEPLOY_DIR"
    cd "$DEPLOY_DIR"
fi
log "Repository: $(git log --oneline -1)"

# ── 4e: Generate .env ────────────────────────────────────────────
log "Generating .env configuration..."
if [ ! -f .env ] || grep -q "CHANGEME" .env 2>/dev/null; then
    GENERATED_PASS=$(openssl rand -hex 8)
    cat > .env <<ENVEOF
ADMIN_PASSWORD=${GENERATED_PASS}
DS_PASSWORD=RedHat123
DB_PASSWORD=RedHat123
PKI_ADMIN_PASSWORD=RedHat123
PKI_TOKEN_PASSWORD=RedHat123
PKI_CLIENT_PKCS12_PASSWORD=RedHat123
PKI_BACKUP_PASSWORD=RedHat123
AWX_SECRET_KEY=$(openssl rand -hex 32)
JUPYTER_TOKEN=$(openssl rand -hex 16)
LAB_DOMAIN=cert-lab.local
HSM_SO_PIN=12345678
HSM_USER_PIN=1234
ENROLLMENT_BACKEND=akamu
SKIP_FREEIPA=1
ENVEOF
    log ".env generated with default passwords"
fi

# ── 4f: Setup DNS ────────────────────────────────────────────────
log "Configuring DNS..."
bash scripts/setup-dns.sh 2>/dev/null || log "WARN: DNS setup incomplete"

# ── 4g: Build hoike image ────────────────────────────────────────
log "Building hoike container image..."
if ! podman image exists localhost/hoike:lab 2>/dev/null; then
    podman build -f containers/hoike/Containerfile \
        -t localhost/hoike:lab containers/hoike/ || log "WARN: hoike build failed"
fi

# ── 4h: Start the lab ────────────────────────────────────────────
log "Starting lab with $PKI_FLAG..."
export NONINTERACTIVE=1
bash start-lab.sh $PKI_FLAG 2>&1 | tee /var/log/cert-lab-deploy.log

log "Deployment complete!"
log "Lab log: /var/log/cert-lab-deploy.log"
DEPLOY_SCRIPT

DEPLOY_EXIT=$?

if [ $DEPLOY_EXIT -ne 0 ]; then
    log_warn "Deployment script exited with code $DEPLOY_EXIT"
    log_info "Check logs: ssh $SSH_USER@$BEAKER_HOSTNAME 'cat /var/log/cert-lab-deploy.log'"
fi

# ── Phase 5: Validation ──────────────────────────────────────────────
log_phase "Phase 5: Validating Deployment"

ssh $SSH_OPTS "$SSH_USER@$BEAKER_HOSTNAME" bash -s -- "$DEPLOY_DIR" <<'VALIDATE_SCRIPT'
#!/bin/bash
DEPLOY_DIR="$1"
cd "$DEPLOY_DIR"

echo "═══ Container Status ═══"
sudo podman ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | \
    grep -E "dogtag|kipuka|akamu|hoike|haproxy|kryoptic|ds-pq" | sort
echo ""

echo "═══ PKI Health ═══"
for ca in dogtag-pq-root-ca dogtag-pq-intermediate-ca dogtag-pq-iot-ca; do
    health=$(sudo podman inspect --format '{{.State.Health.Status}}' "$ca" 2>/dev/null || echo "missing")
    echo "  $ca: $health"
done
echo ""

echo "═══ Enrollment Servers ═══"
for svc in akamu-pq kipuka-pq; do
    health=$(sudo podman inspect --format '{{.State.Health.Status}}' "$svc" 2>/dev/null || echo "missing")
    echo "  $svc: $health"
done
echo ""

echo "═══ Hoike OCSP Fleet ═══"
for svc in hoike-pq-signer hoike-pq-edge-1 hoike-pq-edge-2 haproxy-pq-ocsp; do
    status=$(sudo podman inspect --format '{{.State.Status}}' "$svc" 2>/dev/null || echo "missing")
    echo "  $svc: $status"
done
echo ""

echo "═══ Endpoint Checks ═══"
# ACME directory
if curl -sf http://localhost:8503/directory >/dev/null 2>&1; then
    echo "  ACME directory:  OK (http://localhost:8503/directory)"
else
    echo "  ACME directory:  FAIL"
fi

# EST cacerts
if curl -skf https://localhost:8456/.well-known/est/cacerts >/dev/null 2>&1; then
    echo "  EST cacerts:     OK (https://localhost:8456/.well-known/est/cacerts)"
else
    echo "  EST cacerts:     FAIL"
fi

# Hoike OCSP
if curl -sf http://localhost:2563/ >/dev/null 2>&1; then
    echo "  Hoike OCSP:      OK (http://localhost:2563/)"
else
    echo "  Hoike OCSP:      FAIL"
fi
echo ""
VALIDATE_SCRIPT

# ── Summary ───────────────────────────────────────────────────────────
log_phase "Deployment Complete"

echo "System:     $BEAKER_HOSTNAME"
echo "PKI Mode:   $PKI_MODE"
echo "Branch:     $REPO_BRANCH"
echo "Deploy Dir: $DEPLOY_DIR"
if [ -n "$JOB_ID" ]; then
    echo "Beaker Job: $JOB_ID"
fi
echo ""
echo "Connect:    ssh $SSH_USER@$BEAKER_HOSTNAME"
echo "Lab CLI:    ssh $SSH_USER@$BEAKER_HOSTNAME 'cd $DEPLOY_DIR && ./lab status'"
echo ""
echo "Endpoints (via SSH tunnel):"
echo "  ssh -L 8503:localhost:8503 -L 8456:localhost:8456 -L 2563:localhost:2563 $SSH_USER@$BEAKER_HOSTNAME"
echo "  ACME:  http://localhost:8503/directory"
echo "  EST:   https://localhost:8456/.well-known/est/cacerts"
echo "  OCSP:  http://localhost:2563/"
echo ""
if [ -n "$JOB_ID" ]; then
    echo "Return system when done:"
    echo "  curl -sf -b /tmp/beaker-cookies-*.txt -X POST -H 'Content-Type: application/json' -d '{\"status\":\"Cancelled\"}' ${BEAKER_URL}/bkr-api/jobs/${JOB_ID#J:}/status"
fi
