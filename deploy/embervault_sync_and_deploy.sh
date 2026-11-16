#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="firef0z"
REPO_NAME="embervault"
BRANCH="${BRANCH:-master}"

BASE_DIR="/opt/embervault"
DEPLOY_DIR="/opt/embervault/app"
BIN_DIR="/opt/embervault/bin"
SECRETS_DIR="/opt/embervault/secrets"

GITHUB_TOKEN_FILE="$SECRETS_DIR/.github-token"
COMPOSE_OVERRIDE_FILE="$SECRETS_DIR/docker-compose.proxies.override.yml"
CHOICES_FILE="$SECRETS_DIR/.last_deploy_choices"

REQUIRED_COMMANDS=(git docker)
MISSING_COMMANDS=()

# ============================================================
# Helper per lettura interattiva compatibile con "curl | bash"
# ============================================================

prompt_read() {
  local prompt_msg="$1"
  local var_name="$2"
  if [[ ! -t 0 ]] && [[ -e /dev/tty ]]; then
    read -rp "$prompt_msg" "$var_name" </dev/tty
  else
    read -rp "$prompt_msg" "$var_name"
  fi
}

prompt_read_secret() {
  local prompt_msg="$1"
  local var_name="$2"
  if [[ ! -t 0 ]] && [[ -e /dev/tty ]]; then
    read -rsp "$prompt_msg" "$var_name" </dev/tty
  else
    read -rsp "$prompt_msg" "$var_name"
  fi
}

get_host_ip() {
  local host_ip=""
  if command -v ip >/dev/null 2>&1; then
    host_ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')"
    if [[ -z "$host_ip" ]]; then
      host_ip="$(ip -4 addr show scope global 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]; exit}')"
    fi
  fi
  if [[ -z "$host_ip" ]] && command -v hostname >/dev/null 2>&1; then
    host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  if [[ -z "$host_ip" || "$host_ip" =~ ^127\. ]]; then
    host_ip="localhost"
  fi
  echo "$host_ip"
}

get_proxy_cert_fingerprint() {
  local container="$1"
  local cert_file="${2:-/var/lib/embervault/proxy/tls/cert.pem}"
  local fp=""
  local max_attempts=15
  local attempt=1

  while [[ $attempt -le $max_attempts ]]; do
    if sudo docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$container"; then
      # Prova 1: estrazione diretta del certificato con openssl nel container
      fp="$(sudo docker exec "$container" openssl x509 -in "$cert_file" -noout -fingerprint -sha256 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' :\r\n' | tr '[:upper:]' '[:lower:]')"
      if [[ -n "$fp" && ${#fp} -eq 64 ]]; then
        echo "$fp"
        return 0
      fi

      # Prova 2: lettura dai log di gunicorn/startup del proxy
      fp="$(sudo docker logs "$container" 2>&1 | grep -oE "fingerprint=['\"]?[0-9a-fA-F]{64}['\"]?" | tail -n 1 | grep -oE "[0-9a-fA-F]{64}" | tr '[:upper:]' '[:lower:]')"
      if [[ -n "$fp" && ${#fp} -eq 64 ]]; then
        echo "$fp"
        return 0
      fi
    fi
    sleep 1
    attempt=$((attempt + 1))
  done

  echo "N/A (Certificate not yet generated or container starting)"
  return 1
}

# ============================================================
# Helper per gestione e persistenza scelte di deploy
# ============================================================

display_previous_choices() {
  echo "============================================================"
  echo "Previous deployment choices found:"
  case "${PREV_DEPLOY_ROLE:-}" in
    1|core)
      echo "  - Role: Primary Host (Core: App, DB, Orchestrator)"
      echo "  - Install Public Portal: ${PREV_INSTALL_PORTAL:-false}"
      if [[ "${PREV_INSTALL_PORTAL:-}" != "true" ]]; then
        echo "  - Expose Orchestrator port: ${PREV_EXPOSE_ORCHESTRATOR:-false}"
      fi
      echo "  - Local proxies count: ${PREV_PROXY_COUNT:-0}"
      echo "  - Production mode: ${PREV_PRODUCTION_MODE:-false}"
      ;;
    2|proxy)
      echo "  - Role: External Proxy (Remote Execution Proxy)"
      echo "  - Listening port: ${PREV_PROXY_PORT:-8443}"
      echo "  - Stack name: ${PREV_STACK_NAME:-embervault-proxy}"
      ;;
    3|portal)
      echo "  - Role: External Public Portal (Remote Portal)"
      echo "  - Orchestrator URL: ${PREV_ORCH_URL:-N/A}"
      echo "  - Listening port: ${PREV_PORTAL_PORT:-8083}"
      echo "  - Stack name: ${PREV_STACK_NAME:-embervault-portal}"
      ;;
    4|demo)
      echo "  - Role: Demo Mode (Standalone Demo Instance)"
      echo "  - Web App port: ${PREV_DEMO_APP_PORT:-8088}"
      echo "  - Public Portal port: ${PREV_DEMO_PORTAL_PORT:-8089}"
      if [[ -n "${PREV_DEMO_PUBLIC_URL:-}" ]]; then
        echo "  - Public URL: ${PREV_DEMO_PUBLIC_URL}"
      fi
      echo "  - Stack name: ${PREV_STACK_NAME:-embervault-demo}"
      ;;
    *)
      echo "  - Role: ${PREV_DEPLOY_ROLE:-N/A}"
      ;;
  esac
  echo "============================================================"
}

save_deploy_choices() {
  # Salvataggio delle scelte effettuate su file persistente
  {
    echo "# EmberVault Deployment Configuration"
    echo "# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date)"
    echo "DEPLOY_ROLE=\"$DEPLOY_ROLE\""
    case "$DEPLOY_ROLE" in
      1|core)
        echo "INSTALL_PORTAL=\"$INSTALL_PORTAL\""
        echo "EXPOSE_ORCHESTRATOR=\"$EXPOSE_ORCHESTRATOR\""
        echo "PROXY_COUNT=\"$PROXY_COUNT\""
        echo "PRODUCTION_MODE=\"$PRODUCTION_MODE\""
        if [[ -n "${PREV_PROXY_PORT:-}" ]]; then echo "PROXY_PORT=\"$PREV_PROXY_PORT\""; fi
        if [[ -n "${PREV_ORCH_URL:-}" ]]; then echo "ORCH_URL=\"$PREV_ORCH_URL\""; fi
        if [[ -n "${PREV_PORTAL_PORT:-}" ]]; then echo "PORTAL_PORT=\"$PREV_PORTAL_PORT\""; fi
        if [[ -n "${PREV_DEMO_APP_PORT:-}" ]]; then echo "DEMO_APP_PORT=\"$PREV_DEMO_APP_PORT\""; fi
        if [[ -n "${PREV_DEMO_PORTAL_PORT:-}" ]]; then echo "DEMO_PORTAL_PORT=\"$PREV_DEMO_PORTAL_PORT\""; fi
        if [[ -n "${PREV_STACK_NAME:-}" ]]; then echo "STACK_NAME=\"$PREV_STACK_NAME\""; fi
        ;;
      2|proxy)
        echo "PROXY_PORT=\"$PROXY_PORT\""
        echo "STACK_NAME=\"$STACK_NAME\""
        if [[ -n "${PREV_INSTALL_PORTAL:-}" ]]; then echo "INSTALL_PORTAL=\"$PREV_INSTALL_PORTAL\""; fi
        if [[ -n "${PREV_EXPOSE_ORCHESTRATOR:-}" ]]; then echo "EXPOSE_ORCHESTRATOR=\"$PREV_EXPOSE_ORCHESTRATOR\""; fi
        if [[ -n "${PREV_PROXY_COUNT:-}" ]]; then echo "PROXY_COUNT=\"$PREV_PROXY_COUNT\""; fi
        if [[ -n "${PREV_PRODUCTION_MODE:-}" ]]; then echo "PRODUCTION_MODE=\"$PREV_PRODUCTION_MODE\""; fi
        if [[ -n "${PREV_ORCH_URL:-}" ]]; then echo "ORCH_URL=\"$PREV_ORCH_URL\""; fi
        if [[ -n "${PREV_PORTAL_PORT:-}" ]]; then echo "PORTAL_PORT=\"$PREV_PORTAL_PORT\""; fi
        if [[ -n "${PREV_DEMO_APP_PORT:-}" ]]; then echo "DEMO_APP_PORT=\"$PREV_DEMO_APP_PORT\""; fi
        if [[ -n "${PREV_DEMO_PORTAL_PORT:-}" ]]; then echo "DEMO_PORTAL_PORT=\"$PREV_DEMO_PORTAL_PORT\""; fi
        ;;
      3|portal)
        echo "ORCH_URL=\"$ORCH_URL\""
        echo "PORTAL_PORT=\"$PORTAL_PORT\""
        echo "STACK_NAME=\"$STACK_NAME\""
        if [[ -n "${PREV_INSTALL_PORTAL:-}" ]]; then echo "INSTALL_PORTAL=\"$PREV_INSTALL_PORTAL\""; fi
        if [[ -n "${PREV_EXPOSE_ORCHESTRATOR:-}" ]]; then echo "EXPOSE_ORCHESTRATOR=\"$PREV_EXPOSE_ORCHESTRATOR\""; fi
        if [[ -n "${PREV_PROXY_COUNT:-}" ]]; then echo "PROXY_COUNT=\"$PREV_PROXY_COUNT\""; fi
        if [[ -n "${PREV_PRODUCTION_MODE:-}" ]]; then echo "PRODUCTION_MODE=\"$PREV_PRODUCTION_MODE\""; fi
        if [[ -n "${PREV_PROXY_PORT:-}" ]]; then echo "PROXY_PORT=\"$PREV_PROXY_PORT\""; fi
        if [[ -n "${PREV_DEMO_APP_PORT:-}" ]]; then echo "DEMO_APP_PORT=\"$PREV_DEMO_APP_PORT\""; fi
        if [[ -n "${PREV_DEMO_PORTAL_PORT:-}" ]]; then echo "DEMO_PORTAL_PORT=\"$PREV_DEMO_PORTAL_PORT\""; fi
        ;;
      4|demo)
        echo "DEMO_APP_PORT=\"$DEMO_APP_PORT\""
        echo "DEMO_PORTAL_PORT=\"$DEMO_PORTAL_PORT\""
        if [[ -n "${DEMO_PUBLIC_URL:-}" ]]; then echo "DEMO_PUBLIC_URL=\"$DEMO_PUBLIC_URL\""; fi
        echo "STACK_NAME=\"$STACK_NAME\""
        if [[ -n "${PREV_INSTALL_PORTAL:-}" ]]; then echo "INSTALL_PORTAL=\"$PREV_INSTALL_PORTAL\""; fi
        if [[ -n "${PREV_EXPOSE_ORCHESTRATOR:-}" ]]; then echo "EXPOSE_ORCHESTRATOR=\"$PREV_EXPOSE_ORCHESTRATOR\""; fi
        if [[ -n "${PREV_PROXY_COUNT:-}" ]]; then echo "PROXY_COUNT=\"$PREV_PROXY_COUNT\""; fi
        if [[ -n "${PREV_PRODUCTION_MODE:-}" ]]; then echo "PRODUCTION_MODE=\"$PREV_PRODUCTION_MODE\""; fi
        if [[ -n "${PREV_PROXY_PORT:-}" ]]; then echo "PROXY_PORT=\"$PREV_PROXY_PORT\""; fi
        if [[ -n "${PREV_ORCH_URL:-}" ]]; then echo "ORCH_URL=\"$PREV_ORCH_URL\""; fi
        if [[ -n "${PREV_PORTAL_PORT:-}" ]]; then echo "PORTAL_PORT=\"$PREV_PORTAL_PORT\""; fi
        ;;
    esac
    true
  } | sudo tee "$CHOICES_FILE" >/dev/null
  sudo chmod 600 "$CHOICES_FILE"
}

# ============================================================
# 1. Installazione requisiti di sistema
# ============================================================

for cmd in "${REQUIRED_COMMANDS[@]}"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    MISSING_COMMANDS+=("$cmd")
  fi
done

if [[ ${#MISSING_COMMANDS[@]} -gt 0 ]]; then
  echo "Installing missing requirements: ${MISSING_COMMANDS[*]}..."

  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update

    for cmd in "${MISSING_COMMANDS[@]}"; do
      case "$cmd" in
        git)
          sudo apt-get install -y git
          ;;

        docker)
          sudo apt-get install -y ca-certificates curl
          sudo install -m 0755 -d /etc/apt/keyrings

          if grep -qi '^ID=debian' /etc/os-release; then
            DOCKER_DISTRO="debian"
          else
            DOCKER_DISTRO="ubuntu"
          fi

          sudo curl -fsSL "https://download.docker.com/linux/${DOCKER_DISTRO}/gpg" \
            -o /etc/apt/keyrings/docker.asc
          sudo chmod a+r /etc/apt/keyrings/docker.asc

          echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${DOCKER_DISTRO} $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
            sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

          sudo apt-get update
          sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
          ;;
      esac
    done

  elif command -v dnf >/dev/null 2>&1; then
    for cmd in "${MISSING_COMMANDS[@]}"; do
      case "$cmd" in
        git) sudo dnf install -y git ;;
        docker) sudo dnf install -y docker docker-compose-plugin ;;
      esac
    done

  elif command -v yum >/dev/null 2>&1; then
    for cmd in "${MISSING_COMMANDS[@]}"; do
      case "$cmd" in
        git) sudo yum install -y git ;;
        docker) sudo yum install -y docker docker-compose-plugin ;;
      esac
    done

  elif command -v pacman >/dev/null 2>&1; then
    for cmd in "${MISSING_COMMANDS[@]}"; do
      case "$cmd" in
        git) sudo pacman -S --noconfirm git ;;
        docker) sudo pacman -S --noconfirm docker docker-compose ;;
      esac
    done

  else
    echo "Error: unsupported package manager." >&2
    echo "Please install manually: ${MISSING_COMMANDS[*]}" >&2
    exit 1
  fi
fi

for cmd in "${REQUIRED_COMMANDS[@]}"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: command '$cmd' is not available after installation." >&2
    exit 1
  fi
done

# ============================================================
# 2. Creazione cartelle
# ============================================================

for dir in "$BASE_DIR" "$DEPLOY_DIR" "$BIN_DIR" "$SECRETS_DIR"; do
  if [[ ! -d "$dir" ]]; then
    echo "Creating directory: $dir"
    sudo mkdir -p "$dir"
    sudo chmod 755 "$dir"
  fi
done

# ============================================================
# 3. Autenticazione GitHub & Download Repository
# ============================================================

if ! sudo test -s "$GITHUB_TOKEN_FILE"; then
  echo "GitHub token not found or empty: $GITHUB_TOKEN_FILE"
  prompt_read_secret "Enter GitHub token (leave blank if repository is public): " GITHUB_TOKEN_VALUE
  echo

  if [[ -n "$GITHUB_TOKEN_VALUE" ]]; then
    printf '%s\n' "$GITHUB_TOKEN_VALUE" | sudo tee "$GITHUB_TOKEN_FILE" >/dev/null
    sudo chmod 600 "$GITHUB_TOKEN_FILE"
  fi
  unset GITHUB_TOKEN_VALUE
fi

GITHUB_TOKEN=""
if sudo test -s "$GITHUB_TOKEN_FILE"; then
  GITHUB_TOKEN="$(sudo cat "$GITHUB_TOKEN_FILE" | tr -d '\r\n')"
fi

if [[ -n "$GITHUB_TOKEN" ]]; then
  REPO_URL="https://oauth2:${GITHUB_TOKEN}@github.com/${REPO_OWNER}/${REPO_NAME}.git"
else
  REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
fi

export GIT_TERMINAL_PROMPT=0

if [[ ! -d "$DEPLOY_DIR/.git" ]]; then
  echo "Cloning repository into $DEPLOY_DIR..."
  sudo git clone "$REPO_URL" "$DEPLOY_DIR"
fi

echo "Updating $DEPLOY_DIR from branch $BRANCH..."
sudo git -C "$DEPLOY_DIR" fetch origin "$BRANCH"
sudo git -C "$DEPLOY_DIR" reset --hard "origin/$BRANCH"
sudo git -C "$DEPLOY_DIR" clean -fd

# ============================================================
# 4. Menù di Scelta Modalità di Installazione
# ============================================================

echo
echo "███████╗███╗   ███╗██████╗ ███████╗██████╗ ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗";
echo "██╔════╝████╗ ████║██╔══██╗██╔════╝██╔══██╗██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝";
echo "█████╗  ██╔████╔██║██████╔╝█████╗  ██████╔╝██║   ██║███████║██║   ██║██║     ██║   ";
echo "██╔══╝  ██║╚██╔╝██║██╔══██╗██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ";
echo "███████╗██║ ╚═╝ ██║██████╔╝███████╗██║  ██║ ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ";
echo "╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ";
echo "      D I S T R I B U T E D   B A C K U P   A N D   R E S T O R E   S U I T E      ";
echo "==================================================================================="
echo "                             Automated Deploy & Setup                              "
echo "==================================================================================="

# Caricamento scelte precedenti se presenti
PREV_DEPLOY_ROLE=""
PREV_INSTALL_PORTAL=""
PREV_EXPOSE_ORCHESTRATOR=""
PREV_PROXY_COUNT=""
PREV_PRODUCTION_MODE=""
PREV_PROXY_PORT=""
PREV_STACK_NAME=""
PREV_ORCH_URL=""
PREV_PORTAL_PORT=""
PREV_DEMO_APP_PORT=""
PREV_DEMO_PORTAL_PORT=""
PREV_DEMO_PUBLIC_URL=""
HAS_PREVIOUS_CHOICES=false

if sudo test -s "$CHOICES_FILE"; then
  while IFS='=' read -r key val || [[ -n "$key" ]]; do
    [[ "$key" =~ ^[[:space:]]*# ]] && continue
    key="$(echo "$key" | tr -d '[:space:]')"
    val="$(echo "$val" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")"
    case "$key" in
      DEPLOY_ROLE) PREV_DEPLOY_ROLE="$val" ;;
      INSTALL_PORTAL) PREV_INSTALL_PORTAL="$val" ;;
      EXPOSE_ORCHESTRATOR) PREV_EXPOSE_ORCHESTRATOR="$val" ;;
      PROXY_COUNT) PREV_PROXY_COUNT="$val" ;;
      PRODUCTION_MODE) PREV_PRODUCTION_MODE="$val" ;;
      PROXY_PORT) PREV_PROXY_PORT="$val" ;;
      STACK_NAME) PREV_STACK_NAME="$val" ;;
      ORCH_URL) PREV_ORCH_URL="$val" ;;
      PORTAL_PORT) PREV_PORTAL_PORT="$val" ;;
      DEMO_APP_PORT) PREV_DEMO_APP_PORT="$val" ;;
      DEMO_PORTAL_PORT) PREV_DEMO_PORTAL_PORT="$val" ;;
      DEMO_PUBLIC_URL) PREV_DEMO_PUBLIC_URL="$val" ;;
    esac
  done < <(sudo cat "$CHOICES_FILE")

  if [[ -n "$PREV_DEPLOY_ROLE" ]]; then
    HAS_PREVIOUS_CHOICES=true
  fi
fi

DEPLOY_ROLE="${DEPLOY_ROLE:-}"
REUSE_PREVIOUS_CHOICES="${REUSE_PREVIOUS_CHOICES:-}"

# Se esistono scelte precedenti, chiedi se si desidera riutilizzarle
if [[ "$HAS_PREVIOUS_CHOICES" == "true" ]]; then
  if [[ -z "$DEPLOY_ROLE" || "$DEPLOY_ROLE" == "$PREV_DEPLOY_ROLE" ]]; then
    display_previous_choices
    if [[ -z "$REUSE_PREVIOUS_CHOICES" ]]; then
      prompt_read "Do you want to reuse these previous choices? [Y/n, default: Y]: " REUSE_CHOICE
      REUSE_CHOICE="${REUSE_CHOICE:-Y}"
      if [[ "$REUSE_CHOICE" =~ ^[yYsS]$ ]]; then
        REUSE_PREVIOUS_CHOICES="true"
      else
        REUSE_PREVIOUS_CHOICES="false"
      fi
    fi

    if [[ "$REUSE_PREVIOUS_CHOICES" == "true" ]]; then
      DEPLOY_ROLE="$PREV_DEPLOY_ROLE"
      case "$DEPLOY_ROLE" in
        1|core)
          INSTALL_PORTAL="${PREV_INSTALL_PORTAL:-false}"
          EXPOSE_ORCHESTRATOR="${PREV_EXPOSE_ORCHESTRATOR:-false}"
          PROXY_COUNT="${PREV_PROXY_COUNT:-0}"
          PRODUCTION_MODE="${PREV_PRODUCTION_MODE:-false}"
          ;;
        2|proxy)
          PROXY_PORT="${PREV_PROXY_PORT:-8443}"
          STACK_NAME="${PREV_STACK_NAME:-embervault-proxy}"
          ;;
        3|portal)
          ORCH_URL="${PREV_ORCH_URL:-}"
          PORTAL_PORT="${PREV_PORTAL_PORT:-8083}"
          STACK_NAME="${PREV_STACK_NAME:-embervault-portal}"
          ;;
        4|demo)
          DEMO_APP_PORT="${PREV_DEMO_APP_PORT:-8088}"
          DEMO_PORTAL_PORT="${PREV_DEMO_PORTAL_PORT:-8089}"
          DEMO_PUBLIC_URL="${PREV_DEMO_PUBLIC_URL:-}"
          STACK_NAME="${PREV_STACK_NAME:-embervault-demo}"
          ;;
      esac
    fi
  fi
fi

if [[ -z "$DEPLOY_ROLE" ]]; then
  echo "Select what you want to install on this host:"
  echo "  1) Primary Host (Core services: App, DB, Orchestrator)"
  echo "  2) External Proxy (Remote Execution Proxy)"
  echo "  3) External Public Portal (Remote Public Portal)"
  echo "  4) Demo Mode (Standalone Demo Instance with simulation and sample data)"
  echo "============================================================"
  if [[ -n "$PREV_DEPLOY_ROLE" ]]; then
    prompt_read "Choice [1/2/3/4, default: $PREV_DEPLOY_ROLE (previous)]: " DEPLOY_ROLE
    DEPLOY_ROLE="${DEPLOY_ROLE:-$PREV_DEPLOY_ROLE}"
  else
    prompt_read "Choice [1/2/3/4, default: 1]: " DEPLOY_ROLE
    DEPLOY_ROLE="${DEPLOY_ROLE:-1}"
  fi
fi

case "$DEPLOY_ROLE" in
  1|core)
    echo
    echo "--- Configuration: PRIMARY HOST (CORE) ---"

    # A. Scelta installazione Public Portal locale
    INSTALL_PORTAL="${INSTALL_PORTAL:-}"
    if [[ -z "$INSTALL_PORTAL" ]]; then
      if [[ "${PREV_INSTALL_PORTAL:-}" == "false" ]]; then
        prompt_read "Do you want to install the Public Portal on this host? [y/N, default: N (previous)]: " PORTAL_CHOICE
        PORTAL_CHOICE="${PORTAL_CHOICE:-N}"
      elif [[ "${PREV_INSTALL_PORTAL:-}" == "true" ]]; then
        prompt_read "Do you want to install the Public Portal on this host? [Y/n, default: Y (previous)]: " PORTAL_CHOICE
        PORTAL_CHOICE="${PORTAL_CHOICE:-Y}"
      else
        prompt_read "Do you want to install the Public Portal on this host? [Y/n, default: Y]: " PORTAL_CHOICE
        PORTAL_CHOICE="${PORTAL_CHOICE:-Y}"
      fi
      if [[ "$PORTAL_CHOICE" =~ ^[yYsS]$ ]]; then
        INSTALL_PORTAL="true"
      else
        INSTALL_PORTAL="false"
      fi
    fi

    # B. Se il portal non è locale, chiedere se esporre la porta Orchestrator per un portal esterno
    EXPOSE_ORCHESTRATOR="${EXPOSE_ORCHESTRATOR:-}"
    if [[ "$INSTALL_PORTAL" == "false" && -z "$EXPOSE_ORCHESTRATOR" ]]; then
      echo "The Public Portal will not be installed on this host."
      if [[ "${PREV_EXPOSE_ORCHESTRATOR:-}" == "false" ]]; then
        prompt_read "Do you want to expose the Orchestrator port (8081:8081) to allow connection from an external Public Portal? [y/N, default: N (previous)]: " EXPOSE_CHOICE
        EXPOSE_CHOICE="${EXPOSE_CHOICE:-N}"
      elif [[ "${PREV_EXPOSE_ORCHESTRATOR:-}" == "true" ]]; then
        prompt_read "Do you want to expose the Orchestrator port (8081:8081) to allow connection from an external Public Portal? [Y/n, default: Y (previous)]: " EXPOSE_CHOICE
        EXPOSE_CHOICE="${EXPOSE_CHOICE:-Y}"
      else
        prompt_read "Do you want to expose the Orchestrator port (8081:8081) to allow connection from an external Public Portal? [Y/n, default: Y]: " EXPOSE_CHOICE
        EXPOSE_CHOICE="${EXPOSE_CHOICE:-Y}"
      fi
      if [[ "$EXPOSE_CHOICE" =~ ^[yYsS]$ ]]; then
        EXPOSE_ORCHESTRATOR="true"
      else
        EXPOSE_ORCHESTRATOR="false"
      fi
    elif [[ "$INSTALL_PORTAL" == "true" ]]; then
      # Se il portal è locale sullo stesso host, comunica sulla rete Docker interna
      EXPOSE_ORCHESTRATOR="false"
    fi

    # C. Scelta numero di Proxy locali
    PROXY_COUNT="${PROXY_COUNT:-}"
    if [[ -z "$PROXY_COUNT" ]]; then
      local_proxy_def="${PREV_PROXY_COUNT:-0}"
      if [[ -n "${PREV_PROXY_COUNT:-}" ]]; then
        prompt_read "How many local Proxies do you want to instantiate on this host? [default: $local_proxy_def (previous)]: " PROXY_COUNT
      else
        prompt_read "How many local Proxies do you want to instantiate on this host? [default: 0]: " PROXY_COUNT
      fi
      PROXY_COUNT="${PROXY_COUNT:-$local_proxy_def}"
    fi

    if [[ ! "$PROXY_COUNT" =~ ^[0-9]+$ ]]; then
      echo "Error: proxy count must be a positive integer or zero." >&2
      exit 1
    fi

    # D. Scelta ambiente (Dev/Setup iniziale vs Produzione con autenticazione obbligatoria)
    CORE_ENV_FILE="$SECRETS_DIR/.core-env"
    PRODUCTION_MODE="${PRODUCTION_MODE:-}"
    if [[ -z "$PRODUCTION_MODE" ]]; then
      echo
      echo "------------------------------------------------------------"
      echo "WARNING — Switching to Production mode:"
      echo "Set EMBERVAULT_ENV=prod and EMBERVAULT_DEV_NOAUTH=false"
      echo "ONLY AFTER setting the 'admin' password or creating"
      echo "other administrator accounts via the Web Console."
      echo "If you are running the initial installation, answer 'n'."
      echo "------------------------------------------------------------"
      if [[ "${PREV_PRODUCTION_MODE:-}" == "true" ]]; then
        prompt_read "Do you want to set EMBERVAULT_ENV=prod and EMBERVAULT_DEV_NOAUTH=false? [Y/n, default: Y (previous)]: " PROD_CHOICE
        PROD_CHOICE="${PROD_CHOICE:-Y}"
      elif [[ "${PREV_PRODUCTION_MODE:-}" == "false" ]]; then
        prompt_read "Do you want to set EMBERVAULT_ENV=prod and EMBERVAULT_DEV_NOAUTH=false? [y/N, default: N (previous)]: " PROD_CHOICE
        PROD_CHOICE="${PROD_CHOICE:-N}"
      else
        prompt_read "Do you want to set EMBERVAULT_ENV=prod and EMBERVAULT_DEV_NOAUTH=false? [y/N, default: N]: " PROD_CHOICE
        PROD_CHOICE="${PROD_CHOICE:-N}"
      fi
      if [[ "$PROD_CHOICE" =~ ^[yYsS]$ ]]; then
        PRODUCTION_MODE="true"
      else
        PRODUCTION_MODE="false"
      fi
    fi

    if [[ "$PRODUCTION_MODE" == "true" ]]; then
      CORE_ENV="prod"
      CORE_DEV_NOAUTH="false"
    else
      CORE_ENV="dev"
      CORE_DEV_NOAUTH="true"
    fi

    save_deploy_choices

    {
      echo "EMBERVAULT_ENV=${CORE_ENV}"
      echo "EMBERVAULT_DEV_NOAUTH=${CORE_DEV_NOAUTH}"
    } | sudo tee "$CORE_ENV_FILE" "$DEPLOY_DIR/deploy/compose/.env" >/dev/null
    sudo chmod 600 "$CORE_ENV_FILE" "$DEPLOY_DIR/deploy/compose/.env"

    # E. Generazione Secret di produzione se mancanti
    if command -v python3 >/dev/null 2>&1 && [[ -f "$DEPLOY_DIR/deploy/scripts/generate_secrets.py" ]]; then
      echo "Checking and generating application secrets..."
      python3 "$DEPLOY_DIR/deploy/scripts/generate_secrets.py" --output-dir "$DEPLOY_DIR/deploy/secrets" >/dev/null 2>&1 || true
    fi

    COMPOSE_BASE="$DEPLOY_DIR/deploy/compose/docker-compose.yml"
    COMPOSE_FILES=("-f" "$COMPOSE_BASE")
    COMPOSE_SERVICES=(postgres migrate app orchestrator hook-runner)

    # Se richiesto Portal locale
    if [[ "$INSTALL_PORTAL" == "true" ]]; then
      COMPOSE_SERVICES+=(portal)
    fi

    # Se richiesta esposizione porta Orchestrator (Scenario 3)
    if [[ "$EXPOSE_ORCHESTRATOR" == "true" ]]; then
      EXPOSE_FILE="$DEPLOY_DIR/deploy/compose/docker-compose.expose-orchestrator.yml"
      if [[ -f "$EXPOSE_FILE" ]]; then
        COMPOSE_FILES+=("-f" "$EXPOSE_FILE")
        echo "Orchestrator port exposure (8081:8081) enabled."
      fi
    fi

    # Gestione Proxy locali
    sudo rm -f "$COMPOSE_OVERRIDE_FILE"
    if [[ "$PROXY_COUNT" -gt 0 ]]; then
      echo "Generating configuration for $PROXY_COUNT local proxies..."

      {
        echo "services:"
        for ((i = 1; i <= PROXY_COUNT; i++)); do
          PROXY_TOKEN_FILE="$SECRETS_DIR/.proxy-${i}-token"

          if ! sudo test -s "$PROXY_TOKEN_FILE"; then
            PROXY_TOKEN_VALUE="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
            if [[ ${#PROXY_TOKEN_VALUE} -lt 32 ]]; then
              echo "Error: unable to generate a valid token for proxy $i." >&2
              exit 1
            fi
            printf '%s\n' "$PROXY_TOKEN_VALUE" | sudo tee "$PROXY_TOKEN_FILE" >/dev/null
            sudo chmod 600 "$PROXY_TOKEN_FILE"
            unset PROXY_TOKEN_VALUE
          fi

          PROXY_TOKEN="$(sudo cat "$PROXY_TOKEN_FILE" | tr -d '\r\n')"

          cat <<EOF
  proxy-${i}:
    image: embervault-proxy
    build:
      context: ${DEPLOY_DIR}
      dockerfile: deploy/docker/proxy.Dockerfile
    container_name: embervault-proxy-${i}
    command: ["python3", "-m", "embervault_proxy.main"]
    environment:
      TOKEN: ${PROXY_TOKEN}
      EMBERVAULT_PROXY_PORT: 8443
      EMBERVAULT_PROXY_STATE_DIR: /var/lib/embervault/proxy
      EMBERVAULT_ENV: \${EMBERVAULT_ENV:-prod}
      EMBERVAULT_LOG_FORMAT: \${EMBERVAULT_LOG_FORMAT:-console}
    volumes:
      - proxy${i}_state:/var/lib/embervault/proxy
    networks:
      - proxy_net
    healthcheck:
      test: ["CMD", "python3", "/app/deploy/scripts/healthcheck.py", "--service", "proxy"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 10s
    restart: unless-stopped
EOF
          if [[ "$i" -lt "$PROXY_COUNT" ]]; then
            echo
          fi
        done

        echo
        echo "volumes:"
        for ((i = 1; i <= PROXY_COUNT; i++)); do
          echo "  proxy${i}_state:"
        done
      } | sudo tee "$COMPOSE_OVERRIDE_FILE" >/dev/null

      sudo chmod 600 "$COMPOSE_OVERRIDE_FILE"
      COMPOSE_FILES+=("-f" "$COMPOSE_OVERRIDE_FILE")

      echo "Local proxy tokens saved to:"
      for ((i = 1; i <= PROXY_COUNT; i++)); do
        echo "  proxy-${i}: $SECRETS_DIR/.proxy-${i}-token"
        COMPOSE_SERVICES+=("proxy-${i}")
      done
    fi

    echo
    echo "Starting Docker Compose stack for Primary Host..."
    sudo env \
      EMBERVAULT_ENV="$CORE_ENV" \
      EMBERVAULT_DEV_NOAUTH="$CORE_DEV_NOAUTH" \
      docker compose \
        -p embervault \
        "${COMPOSE_FILES[@]}" \
        up -d --build \
        "${COMPOSE_SERVICES[@]}"

    HOST_IP="${HOST_IP:-$(get_host_ip)}"

    echo
    echo "============================================================"
    echo "  Primary Host deploy completed successfully!"
    echo "  - Web App Console:       http://${HOST_IP}:8080"
    if [[ "$INSTALL_PORTAL" == "true" ]]; then
      echo "  - Public Portal:         http://${HOST_IP}:8083"
    fi
    if [[ "$EXPOSE_ORCHESTRATOR" == "true" ]]; then
      echo "  - Orchestrator Port:     0.0.0.0:8081 (exposed for external Public Portal)"
    fi
    echo "  - Environment (ENV):     $CORE_ENV (EMBERVAULT_DEV_NOAUTH=$CORE_DEV_NOAUTH)"
    echo "  - Active local proxies:  $PROXY_COUNT"
    if [[ "$PROXY_COUNT" -gt 0 ]]; then
      echo "------------------------------------------------------------"
      echo "  Local Execution Proxies Details (for Web Console TOFU registration):"
      for ((i = 1; i <= PROXY_COUNT; i++)); do
        p_container="embervault-proxy-${i}"
        p_token_file="$SECRETS_DIR/.proxy-${i}-token"
        p_token="$(sudo cat "$p_token_file" 2>/dev/null | tr -d '\r\n')"
        p_fp="$(get_proxy_cert_fingerprint "$p_container")"
        echo
        echo "  [ Proxy #${i} (container: ${p_container}) ]"
        echo "    * Host / IP:           proxy-${i} (internal Docker) or ${HOST_IP}"
        echo "    * Port:                8443"
        echo "    * Token:               ${p_token}"
        echo "    * Certificate (SHA256): ${p_fp}"
      done
    fi
    echo "============================================================"
    ;;

  2|proxy)
    echo
    echo "--- Configuration: EXTERNAL PROXY (REMOTE EXECUTION PROXY) ---"

    PROXY_TOKEN_FILE="$SECRETS_DIR/.proxy-token"

    if ! sudo test -s "$PROXY_TOKEN_FILE"; then
      echo "Enter PROXY_TOKEN (or press ENTER to generate a new one):"
      prompt_read_secret "Token: " PROXY_TOKEN_INPUT
      echo

      if [[ -z "$PROXY_TOKEN_INPUT" ]]; then
        PROXY_TOKEN_INPUT="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
        echo "Generated new random PROXY_TOKEN."
      fi

      if [[ ${#PROXY_TOKEN_INPUT} -lt 32 ]]; then
        echo "Error: PROXY_TOKEN must contain at least 32 characters." >&2
        exit 1
      fi

      printf '%s\n' "$PROXY_TOKEN_INPUT" | sudo tee "$PROXY_TOKEN_FILE" >/dev/null
      sudo chmod 600 "$PROXY_TOKEN_FILE"
      unset PROXY_TOKEN_INPUT
    fi

    PROXY_TOKEN="$(sudo cat "$PROXY_TOKEN_FILE" | tr -d '\r\n')"

    PROXY_PORT="${PROXY_PORT:-}"
    if [[ -z "$PROXY_PORT" ]]; then
      default_proxy_port="${PREV_PROXY_PORT:-8443}"
      if [[ -n "${PREV_PROXY_PORT:-}" ]]; then
        prompt_read "Proxy listening port on host [default: $default_proxy_port (previous)]: " PROXY_PORT
      else
        prompt_read "Proxy listening port on host [default: 8443]: " PROXY_PORT
      fi
      PROXY_PORT="${PROXY_PORT:-$default_proxy_port}"
    fi

    STACK_NAME="${STACK_NAME:-}"
    if [[ -z "$STACK_NAME" ]]; then
      default_proxy_stack="${PREV_STACK_NAME:-embervault-proxy}"
      if [[ -n "${PREV_STACK_NAME:-}" ]]; then
        prompt_read "Docker Compose stack name [default: $default_proxy_stack (previous)]: " STACK_NAME
      else
        prompt_read "Docker Compose stack name [default: embervault-proxy]: " STACK_NAME
      fi
      STACK_NAME="${STACK_NAME:-$default_proxy_stack}"
    fi

    save_deploy_choices

    COMPOSE_PROXY_FILE="$DEPLOY_DIR/deploy/compose/docker-compose.proxy.yml"
    if [[ ! -f "$COMPOSE_PROXY_FILE" ]]; then
      echo "Error: $COMPOSE_PROXY_FILE not found." >&2
      exit 1
    fi

    echo "Starting Docker Compose stack for External Proxy: $STACK_NAME..."
    sudo env \
      PROXY_TOKEN="$PROXY_TOKEN" \
      EMBERVAULT_PROXY_PORT="$PROXY_PORT" \
      docker compose \
        -p "$STACK_NAME" \
        -f "$COMPOSE_PROXY_FILE" \
        up -d --build

    EXTERNAL_PROXY_CONTAINER="embervault-proxy"
    EXTERNAL_PROXY_FP="$(get_proxy_cert_fingerprint "$EXTERNAL_PROXY_CONTAINER")"

    echo
    echo "============================================================"
    echo "  External Proxy deploy completed successfully!"
    echo "  - Stack:                 $STACK_NAME"
    echo "  - Listening port:        $PROXY_PORT"
    echo "  - PROXY_TOKEN saved to:  $PROXY_TOKEN_FILE"
    echo
    echo "  Registration Details (for EmberVault Web Console TOFU registration):"
    echo "    * Host / IP:           $(get_host_ip)"
    echo "    * HTTPS Port:          $PROXY_PORT"
    echo "    * Token:               $PROXY_TOKEN"
    echo "    * Certificate (SHA256): $EXTERNAL_PROXY_FP"
    echo "============================================================"
    unset PROXY_TOKEN
    ;;

  3|portal)
    echo
    echo "--- Configuration: EXTERNAL PUBLIC PORTAL (REMOTE PORTAL) ---"

    ORCH_URL="${ORCH_URL:-}"
    if [[ -z "$ORCH_URL" ]]; then
      if [[ -n "${PREV_ORCH_URL:-}" ]]; then
        prompt_read "Enter central Orchestrator URL [default: $PREV_ORCH_URL (previous)]: " ORCH_URL
        ORCH_URL="${ORCH_URL:-$PREV_ORCH_URL}"
      else
        prompt_read "Enter central Orchestrator URL (e.g. http://192.168.1.100:8081): " ORCH_URL
      fi
    fi
    if [[ -z "$ORCH_URL" ]]; then
      echo "Error: Orchestrator URL cannot be empty." >&2
      exit 1
    fi

    PORTAL_KEY_FILE="$SECRETS_DIR/.portal-secret-key"
    if ! sudo test -s "$PORTAL_KEY_FILE"; then
      echo "Enter PORTAL_SECRET_KEY (or press ENTER to generate a random one):"
      prompt_read_secret "Secret key: " PORTAL_KEY_INPUT
      echo

      if [[ -z "$PORTAL_KEY_INPUT" ]]; then
        PORTAL_KEY_INPUT="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
        echo "Generated new random secret key for Portal sessions."
      fi

      if [[ ${#PORTAL_KEY_INPUT} -lt 32 ]]; then
        echo "Error: secret key must contain at least 32 characters." >&2
        exit 1
      fi

      printf '%s\n' "$PORTAL_KEY_INPUT" | sudo tee "$PORTAL_KEY_FILE" >/dev/null
      sudo chmod 600 "$PORTAL_KEY_FILE"
      unset PORTAL_KEY_INPUT
    fi

    PORTAL_KEY="$(sudo cat "$PORTAL_KEY_FILE" | tr -d '\r\n')"

    PORTAL_PORT="${PORTAL_PORT:-}"
    if [[ -z "$PORTAL_PORT" ]]; then
      default_portal_port="${PREV_PORTAL_PORT:-8083}"
      if [[ -n "${PREV_PORTAL_PORT:-}" ]]; then
        prompt_read "Public Portal listening port on host [default: $default_portal_port (previous)]: " PORTAL_PORT
      else
        prompt_read "Public Portal listening port on host [default: 8083]: " PORTAL_PORT
      fi
      PORTAL_PORT="${PORTAL_PORT:-$default_portal_port}"
    fi

    STACK_NAME="${STACK_NAME:-}"
    if [[ -z "$STACK_NAME" ]]; then
      default_portal_stack="${PREV_STACK_NAME:-embervault-portal}"
      if [[ -n "${PREV_STACK_NAME:-}" ]]; then
        prompt_read "Docker Compose stack name [default: $default_portal_stack (previous)]: " STACK_NAME
      else
        prompt_read "Docker Compose stack name [default: embervault-portal]: " STACK_NAME
      fi
      STACK_NAME="${STACK_NAME:-$default_portal_stack}"
    fi

    save_deploy_choices

    COMPOSE_PORTAL_FILE="$DEPLOY_DIR/deploy/compose/docker-compose.portal.yml"
    if [[ ! -f "$COMPOSE_PORTAL_FILE" ]]; then
      echo "Error: $COMPOSE_PORTAL_FILE not found." >&2
      exit 1
    fi

    echo "Starting Docker Compose stack for Public Portal: $STACK_NAME..."
    sudo env \
      EMBERVAULT_ORCHESTRATOR_URL="$ORCH_URL" \
      PORTAL_SECRET_KEY="$PORTAL_KEY" \
      PORTAL_PORT="$PORTAL_PORT" \
      docker compose \
        -p "$STACK_NAME" \
        -f "$COMPOSE_PORTAL_FILE" \
        up -d --build

    HOST_IP="${HOST_IP:-$(get_host_ip)}"

    echo
    echo "============================================================"
    echo "  External Public Portal deploy completed successfully!"
    echo "  - Stack:                 $STACK_NAME"
    echo "  - Listening port:        $PORTAL_PORT"
    echo "  - Connected to Orch URL: $ORCH_URL"
    echo "  - Portal reachable at:   http://${HOST_IP}:$PORTAL_PORT"
    echo "============================================================"
    unset PORTAL_KEY
    ;;

  4|demo)
    echo
    echo "--- Configuration: DEMO MODE (STANDALONE DEMO INSTANCE) ---"
    echo "This mode deploys an independent EmberVault instance with pre-configured"
    echo "demo credentials, sample remotes/proxies, and safe simulated job execution."
    echo

    DEMO_APP_PORT="${DEMO_APP_PORT:-}"
    if [[ -z "$DEMO_APP_PORT" ]]; then
      default_demo_port="${PREV_DEMO_APP_PORT:-8088}"
      if [[ -n "${PREV_DEMO_APP_PORT:-}" ]]; then
        prompt_read "Web App listening port on host [default: $default_demo_port (previous)]: " DEMO_APP_PORT
      else
        prompt_read "Web App listening port on host [default: 8088]: " DEMO_APP_PORT
      fi
      DEMO_APP_PORT="${DEMO_APP_PORT:-$default_demo_port}"
    fi

    if [[ ! "$DEMO_APP_PORT" =~ ^[0-9]+$ ]]; then
      echo "Error: port must be a positive integer." >&2
      exit 1
    fi

    DEMO_PORTAL_PORT="${DEMO_PORTAL_PORT:-}"
    if [[ -z "$DEMO_PORTAL_PORT" ]]; then
      default_demo_portal="${PREV_DEMO_PORTAL_PORT:-8089}"
      if [[ -n "${PREV_DEMO_PORTAL_PORT:-}" ]]; then
        prompt_read "Public Portal listening port on host [default: $default_demo_portal (previous)]: " DEMO_PORTAL_PORT
      else
        prompt_read "Public Portal listening port on host [default: 8089]: " DEMO_PORTAL_PORT
      fi
      DEMO_PORTAL_PORT="${DEMO_PORTAL_PORT:-$default_demo_portal}"
    fi

    if [[ ! "$DEMO_PORTAL_PORT" =~ ^[0-9]+$ ]]; then
      echo "Error: portal port must be a positive integer." >&2
      exit 1
    fi

    STACK_NAME="${STACK_NAME:-}"
    if [[ -z "$STACK_NAME" ]]; then
      default_demo_stack="${PREV_STACK_NAME:-embervault-demo}"
      if [[ -n "${PREV_STACK_NAME:-}" ]]; then
        prompt_read "Docker Compose project/stack name [default: $default_demo_stack (previous)]: " STACK_NAME
      else
        prompt_read "Docker Compose project/stack name [default: embervault-demo]: " STACK_NAME
      fi
      STACK_NAME="${STACK_NAME:-$default_demo_stack}"
    fi

    HOST_IP="${HOST_IP:-$(get_host_ip)}"
    default_demo_url="${PREV_DEMO_PUBLIC_URL:-${EMBERVAULT_PUBLIC_URL:-http://${HOST_IP}:${DEMO_APP_PORT}}}"
    DEMO_PUBLIC_URL="${DEMO_PUBLIC_URL:-}"
    if [[ -z "$DEMO_PUBLIC_URL" ]]; then
      if [[ -n "${PREV_DEMO_PUBLIC_URL:-}" || -n "${EMBERVAULT_PUBLIC_URL:-}" ]]; then
        prompt_read "Public URL for Demo Instance [default: $default_demo_url]: " DEMO_PUBLIC_URL
      fi
      DEMO_PUBLIC_URL="${DEMO_PUBLIC_URL:-$default_demo_url}"
    fi

    DEMO_URL="$DEMO_PUBLIC_URL"
    if [[ -n "${EMBERVAULT_PORTAL_URL:-}" ]]; then
      DEMO_PORTAL_URL="$EMBERVAULT_PORTAL_URL"
    elif [[ "$DEMO_URL" =~ :[0-9]+ ]]; then
      DEMO_PORTAL_URL="$(echo "$DEMO_URL" | sed -E "s/:[0-9]+(\/|$)/:${DEMO_PORTAL_PORT}\1/")"
    else
      DEMO_PORTAL_URL="$DEMO_URL"
    fi

    save_deploy_choices

    # Secret generation if missing
    if command -v python3 >/dev/null 2>&1 && [[ -f "$DEPLOY_DIR/deploy/scripts/generate_secrets.py" ]]; then
      python3 "$DEPLOY_DIR/deploy/scripts/generate_secrets.py" --output-dir "$DEPLOY_DIR/deploy/secrets" >/dev/null 2>&1 || true
    fi

    COMPOSE_BASE="$DEPLOY_DIR/deploy/compose/docker-compose.yml"
    COMPOSE_DEMO="$DEPLOY_DIR/deploy/compose/docker-compose.demo.yml"
    if [[ ! -f "$COMPOSE_DEMO" ]]; then
      echo "Error: $COMPOSE_DEMO not found." >&2
      exit 1
    fi

    echo "Starting Docker Compose stack for Demo Mode: $STACK_NAME (App: $DEMO_APP_PORT, Portal: $DEMO_PORTAL_PORT)..."
    sudo env \
      EMBERVAULT_DEMO_MODE="true" \
      EMBERVAULT_ENV="dev" \
      EMBERVAULT_DEV_NOAUTH="false" \
      EMBERVAULT_MASTER_KEY="${EMBERVAULT_MASTER_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}" \
      EMBERVAULT_APP_PORT="$DEMO_APP_PORT" \
      DEMO_APP_PORT="$DEMO_APP_PORT" \
      PORTAL_PORT="$DEMO_PORTAL_PORT" \
      DEMO_PORTAL_PORT="$DEMO_PORTAL_PORT" \
      EMBERVAULT_PUBLIC_URL="$DEMO_URL" \
      EMBERVAULT_PORTAL_URL="$DEMO_PORTAL_URL" \
      docker compose \
        -p "$STACK_NAME" \
        -f "$COMPOSE_BASE" \
        -f "$COMPOSE_DEMO" \
        up -d --build \
        postgres migrate app orchestrator hook-runner portal

    echo
    echo "============================================================"
    echo "  EmberVault Demo Mode deploy completed successfully!"
    echo "  - Web App Console URL:   ${DEMO_URL}"
    echo "  - Public Portal URL:     ${DEMO_PORTAL_URL}"
    echo "  - Username:              demo"
    echo "  - Password:              demo"
    echo "  - Stack Name:            $STACK_NAME"
    echo "  - Mode:                  DEMO (safe simulated jobs, remotes & portal)"
    echo "============================================================"
    ;;

  *)
    echo "Error: invalid choice: $DEPLOY_ROLE. Choose 1, 2, 3, or 4 (or 'demo')." >&2
    exit 1
    ;;
esac
