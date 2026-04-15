#!/usr/bin/env bash
# Setup Ansible Semaphore (v2.17.16) for Certificate Revocation Lab
# Configures project, keys, repository, inventories, environments, and task templates
# Idempotent - checks for existing resources before creating

set -euo pipefail

###############################################################################
# Configuration
###############################################################################
SEMAPHORE_URL="http://192.168.1.121:3010"
ADMIN_USER="admin"
ADMIN_PASS="54HKVi5QiBlo5J2b2LdAnbTimKzCNzWJ"
COOKIE_JAR=$(mktemp)
PKI_ADMIN_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123}"
SSH_KEY_FILE="${SSH_KEY_FILE:-/home/certlab/.ssh/id_ed25519}"

PROJECT_NAME="Certificate Revocation Lab"

# Cleanup on exit
trap 'rm -f "$COOKIE_JAR"' EXIT

###############################################################################
# Color output
###############################################################################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()    { echo -e "${BLUE}[INFO]${NC}  $*" >&2; }
success() { echo -e "${GREEN}[OK]${NC}    $*" >&2; }
warn()    { echo -e "${YELLOW}[SKIP]${NC}  $*" >&2; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
section() { echo -e "\n${CYAN}=== $* ===${NC}" >&2; }

###############################################################################
# API helpers
###############################################################################
login() {
    info "Authenticating to Semaphore at ${SEMAPHORE_URL}..."
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -c "$COOKIE_JAR" \
        -H "Content-Type: application/json" \
        -d "{\"auth\": \"${ADMIN_USER}\", \"password\": \"${ADMIN_PASS}\"}" \
        "${SEMAPHORE_URL}/api/auth/login")
    if [[ "$http_code" -ne 204 && "$http_code" -ne 200 ]]; then
        error "Login failed (HTTP ${http_code})"
        exit 1
    fi
    success "Authenticated as ${ADMIN_USER}"
}

api_get() {
    local path="$1"
    curl -s -b "$COOKIE_JAR" \
        -H "Content-Type: application/json" \
        "${SEMAPHORE_URL}${path}"
}

api_post() {
    local path="$1"
    local data="$2"
    local body_file
    body_file=$(mktemp)
    local http_code
    http_code=$(curl -s -o "$body_file" -w "%{http_code}" \
        -b "$COOKIE_JAR" \
        -H "Content-Type: application/json" \
        -d "$data" \
        "${SEMAPHORE_URL}${path}")
    local body
    body=$(cat "$body_file")
    rm -f "$body_file"
    # Return body on stdout, http_code on fd3
    echo "$body"
    return $(( http_code >= 200 && http_code < 300 ? 0 : 1 ))
}

api_post_check() {
    local path="$1"
    local data="$2"
    local label="$3"
    local body
    if body=$(api_post "$path" "$data"); then
        success "Created: ${label}"
        echo "$body"
    else
        error "Failed to create ${label}"
        echo "$body" >&2
        return 1
    fi
}

###############################################################################
# Resource creation functions
###############################################################################

create_project() {
    section "Project"
    local existing
    existing=$(api_get "/api/projects")
    local project_id
    project_id=$(echo "$existing" | jq -r ".[] | select(.name == \"${PROJECT_NAME}\") | .id" 2>/dev/null)

    if [[ -n "$project_id" && "$project_id" != "null" ]]; then
        warn "Project '${PROJECT_NAME}' already exists (id=${project_id})"
        echo "$project_id"
        return
    fi

    local result
    result=$(api_post_check "/api/projects" \
        "{\"name\": \"${PROJECT_NAME}\", \"type\": \"\"}" \
        "${PROJECT_NAME}") || exit 1
    project_id=$(echo "$result" | jq -r '.id')
    echo "$project_id"
}

create_key() {
    local project_id="$1"
    local name="$2"
    local key_type="$3"
    shift 3

    # Check if key already exists
    local existing
    existing=$(api_get "/api/project/${project_id}/keys")
    local key_id
    key_id=$(echo "$existing" | jq -r ".[] | select(.name == \"${name}\") | .id" 2>/dev/null)

    if [[ -n "$key_id" && "$key_id" != "null" ]]; then
        warn "Key '${name}' already exists (id=${key_id})"
        echo "$key_id"
        return
    fi

    local payload
    case "$key_type" in
        none)
            payload=$(jq -n \
                --arg name "$name" \
                --argjson pid "$project_id" \
                '{
                    name: $name,
                    project_id: $pid,
                    type: "none"
                }')
            ;;
        ssh)
            local ssh_key="$1"
            payload=$(jq -n \
                --arg name "$name" \
                --argjson pid "$project_id" \
                --arg key "$ssh_key" \
                '{
                    name: $name,
                    project_id: $pid,
                    type: "ssh",
                    ssh: {
                        private_key: $key
                    }
                }')
            ;;
        login_password)
            local login="$1"
            local password="$2"
            payload=$(jq -n \
                --arg name "$name" \
                --argjson pid "$project_id" \
                --arg login "$login" \
                --arg pass "$password" \
                '{
                    name: $name,
                    project_id: $pid,
                    type: "login_password",
                    login_password: {
                        login: $login,
                        password: $pass
                    }
                }')
            ;;
    esac

    local result
    result=$(api_post_check "/api/project/${project_id}/keys" "$payload" "Key: ${name}") || return 1
    echo "$result" | jq -r '.id'
}

create_repository() {
    local project_id="$1"
    local name="$2"
    local git_url="$3"
    local branch="$4"
    local ssh_key_id="$5"

    section "Repository"

    local existing
    existing=$(api_get "/api/project/${project_id}/repositories")
    local repo_id
    repo_id=$(echo "$existing" | jq -r ".[] | select(.name == \"${name}\") | .id" 2>/dev/null)

    if [[ -n "$repo_id" && "$repo_id" != "null" ]]; then
        warn "Repository '${name}' already exists (id=${repo_id})"
        echo "$repo_id"
        return
    fi

    local payload
    payload=$(jq -n \
        --arg name "$name" \
        --argjson pid "$project_id" \
        --arg url "$git_url" \
        --arg branch "$branch" \
        --argjson kid "$ssh_key_id" \
        '{
            name: $name,
            project_id: $pid,
            git_url: $url,
            git_branch: $branch,
            ssh_key_id: $kid
        }')

    local result
    result=$(api_post_check "/api/project/${project_id}/repositories" "$payload" "Repository: ${name}") || return 1
    echo "$result" | jq -r '.id'
}

create_inventory() {
    local project_id="$1"
    local name="$2"
    local inv_type="$3"
    local inventory="$4"
    local ssh_key_id="$5"

    local existing
    existing=$(api_get "/api/project/${project_id}/inventory")
    local inv_id
    inv_id=$(echo "$existing" | jq -r ".[] | select(.name == \"${name}\") | .id" 2>/dev/null)

    if [[ -n "$inv_id" && "$inv_id" != "null" ]]; then
        warn "Inventory '${name}' already exists (id=${inv_id})"
        echo "$inv_id"
        return
    fi

    local payload
    payload=$(jq -n \
        --arg name "$name" \
        --argjson pid "$project_id" \
        --arg type "$inv_type" \
        --arg inv "$inventory" \
        --argjson kid "$ssh_key_id" \
        '{
            name: $name,
            project_id: $pid,
            type: $type,
            inventory: $inv,
            ssh_key_id: $kid
        }')

    local result
    result=$(api_post_check "/api/project/${project_id}/inventory" "$payload" "Inventory: ${name}") || return 1
    echo "$result" | jq -r '.id'
}

create_environment() {
    local project_id="$1"
    local name="$2"
    local extra_vars="$3"
    local env_vars="$4"

    local existing
    existing=$(api_get "/api/project/${project_id}/environment")
    local env_id
    env_id=$(echo "$existing" | jq -r ".[] | select(.name == \"${name}\") | .id" 2>/dev/null)

    if [[ -n "$env_id" && "$env_id" != "null" ]]; then
        warn "Environment '${name}' already exists (id=${env_id})"
        echo "$env_id"
        return
    fi

    local payload
    payload=$(jq -n \
        --arg name "$name" \
        --argjson pid "$project_id" \
        --arg extra "$extra_vars" \
        --arg env "$env_vars" \
        '{
            name: $name,
            project_id: $pid,
            json: $extra,
            env: $env
        }')

    local result
    result=$(api_post_check "/api/project/${project_id}/environment" "$payload" "Environment: ${name}") || return 1
    echo "$result" | jq -r '.id'
}

create_template() {
    local project_id="$1"
    local name="$2"
    local playbook="$3"
    local env_id="$4"
    local inv_id="$5"
    local repo_id="$6"

    local existing
    existing=$(api_get "/api/project/${project_id}/templates")
    local tmpl_id
    tmpl_id=$(echo "$existing" | jq -r ".[] | select(.name == \"${name}\") | .id" 2>/dev/null)

    if [[ -n "$tmpl_id" && "$tmpl_id" != "null" ]]; then
        warn "Template '${name}' already exists (id=${tmpl_id})"
        echo "$tmpl_id"
        return 0
    fi

    local payload
    payload=$(jq -n \
        --arg name "$name" \
        --argjson pid "$project_id" \
        --arg playbook "$playbook" \
        --argjson eid "$env_id" \
        --argjson iid "$inv_id" \
        --argjson rid "$repo_id" \
        '{
            name: $name,
            project_id: $pid,
            playbook: $playbook,
            environment_id: $eid,
            inventory_id: $iid,
            repository_id: $rid,
            app: "ansible",
            allow_override_args_in_task: true
        }')

    local result
    result=$(api_post_check "/api/project/${project_id}/templates" "$payload" "Template: ${name}") || return 1
    echo "$result" | jq -r '.id'
}

create_schedule() {
    local project_id="$1"
    local template_id="$2"
    local name="$3"
    local cron="$4"

    # Check if schedule already exists
    local existing
    existing=$(api_get "/api/project/${project_id}/schedules")
    local sched_id
    sched_id=$(echo "$existing" | jq -r ".[] | select(.name == \"${name}\") | .id" 2>/dev/null)

    if [[ -n "$sched_id" && "$sched_id" != "null" ]]; then
        warn "Schedule '${name}' already exists (id=${sched_id})"
        return 0
    fi

    local payload
    payload=$(jq -n \
        --argjson pid "$project_id" \
        --argjson tid "$template_id" \
        --arg name "$name" \
        --arg cron "$cron" \
        '{
            project_id: $pid,
            template_id: $tid,
            name: $name,
            cron_format: $cron
        }')

    local result
    result=$(api_post_check "/api/project/${project_id}/schedules" "$payload" "Schedule: ${name}") || return 1
    sched_id=$(echo "$result" | jq -r '.id')

    # Activate the schedule (created inactive by default)
    local activate_payload
    activate_payload=$(jq -n \
        --argjson id "$sched_id" \
        --argjson pid "$project_id" \
        --argjson tid "$template_id" \
        --arg name "$name" \
        --arg cron "$cron" \
        '{
            id: $id,
            project_id: $pid,
            template_id: $tid,
            name: $name,
            cron_format: $cron,
            active: true
        }')

    local body_file
    body_file=$(mktemp)
    local http_code
    http_code=$(curl -s -o "$body_file" -w "%{http_code}" \
        -b "$COOKIE_JAR" \
        -H "Content-Type: application/json" \
        -X PUT \
        -d "$activate_payload" \
        "${SEMAPHORE_URL}/api/project/${project_id}/schedules/${sched_id}")
    rm -f "$body_file"

    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
        success "Activated: Schedule '${name}'"
    else
        error "Failed to activate schedule '${name}' (HTTP ${http_code})"
    fi
}

###############################################################################
# Main
###############################################################################
main() {
    echo -e "${CYAN}============================================${NC}" >&2
    echo -e "${CYAN}  Ansible Semaphore Setup                   ${NC}" >&2
    echo -e "${CYAN}  Certificate Revocation Lab                ${NC}" >&2
    echo -e "${CYAN}============================================${NC}" >&2

    # Verify prerequisites
    for cmd in curl jq; do
        if ! command -v "$cmd" &>/dev/null; then
            error "Required command not found: ${cmd}"
            exit 1
        fi
    done

    # Read SSH key
    if [[ ! -f "$SSH_KEY_FILE" ]]; then
        error "SSH key not found: ${SSH_KEY_FILE}"
        exit 1
    fi
    local ssh_private_key
    ssh_private_key=$(cat "$SSH_KEY_FILE")
    info "Loaded SSH key from ${SSH_KEY_FILE}"

    # Login
    login

    # 1. Create project
    local project_id
    project_id=$(create_project)
    info "Project ID: ${project_id}"

    # 2. Create keys
    section "Key Store"

    local key_none_id key_ssh_id key_gitlab_id key_pki_id

    key_none_id=$(create_key "$project_id" "None" "none")
    info "Key 'None' ID: ${key_none_id}"

    key_ssh_id=$(create_key "$project_id" "Lab Host SSH" "ssh" "$ssh_private_key")
    info "Key 'Lab Host SSH' ID: ${key_ssh_id}"

    key_gitlab_id=$(create_key "$project_id" "GitLab SSH" "ssh" "$ssh_private_key")
    info "Key 'GitLab SSH' ID: ${key_gitlab_id}"

    key_pki_id=$(create_key "$project_id" "PKI Admin Password" "login_password" "caadmin" "$PKI_ADMIN_PASSWORD")
    info "Key 'PKI Admin Password' ID: ${key_pki_id}"

    # 3. Create repository
    local repo_id
    repo_id=$(create_repository "$project_id" \
        "cert-revocation-lab" \
        "ssh://git@localhost:2222/heebus/cert-revocation-lab.git" \
        "main" \
        "$key_gitlab_id")
    info "Repository ID: ${repo_id}"

    # 4. Create inventories
    section "Inventories"

    local inv_localhost_id inv_pki_id

    inv_localhost_id=$(create_inventory "$project_id" \
        "Lab Localhost" "file" "ansible/inventory/semaphore.yml" "$key_ssh_id")
    info "Inventory 'Lab Localhost' ID: ${inv_localhost_id}"

    inv_pki_id=$(create_inventory "$project_id" \
        "PKI Containers" "file" "ansible/inventory/pki_hosts.yml" "$key_ssh_id")
    info "Inventory 'PKI Containers' ID: ${inv_pki_id}"

    # 5. Create environments
    section "Environments"

    # Common env vars for all environments
    local env_vars
    env_vars=$(jq -n '{
        ADMIN_PASSWORD: "RedHat123",
        PKI_ADMIN_PASSWORD: "RedHat123",
        PKI_TOKEN_PASSWORD: "RedHat123",
        DS_PASSWORD: "RedHat123",
        LAB_HOST_IP: "localhost",
        LAB_HOST_USER: "certlab",
        LAB_ROOT_DIR: "/home/certlab/cert-revocation-lab"
    }' | jq -c .)

    local env_default_id env_rsa_id env_ecc_id env_pqc_id env_all_id env_ir_id

    env_default_id=$(create_environment "$project_id" "Default" '{"backup_dir": "/tmp/cert-lab-backups"}' "$env_vars")
    info "Environment 'Default' ID: ${env_default_id}"

    env_rsa_id=$(create_environment "$project_id" "RSA PKI" \
        '{"pki_type": "rsa", "pki_mode": "rsa"}' "$env_vars")
    info "Environment 'RSA PKI' ID: ${env_rsa_id}"

    env_ecc_id=$(create_environment "$project_id" "ECC PKI" \
        '{"pki_type": "ecc", "pki_mode": "ecc"}' "$env_vars")
    info "Environment 'ECC PKI' ID: ${env_ecc_id}"

    env_pqc_id=$(create_environment "$project_id" "PQC PKI" \
        '{"pki_type": "pqc", "pki_mode": "pqc"}' "$env_vars")
    info "Environment 'PQC PKI' ID: ${env_pqc_id}"

    env_all_id=$(create_environment "$project_id" "All PKI" \
        '{"pki_type": "all", "pki_mode": "all"}' "$env_vars")
    info "Environment 'All PKI' ID: ${env_all_id}"

    env_ir_id=$(create_environment "$project_id" "Incident Response" \
        '{"auto_reissue": true, "severity": "critical", "notify_channels": ["log", "kafka"]}' "$env_vars")
    info "Environment 'Incident Response' ID: ${env_ir_id}"

    # 6. Create task templates
    section "Task Templates - Operations"

    local -a ops_templates=(
        "Lab Start|ansible/playbooks/ops/lab-start.yml|${env_all_id}|${inv_localhost_id}"
        "Lab Stop|ansible/playbooks/ops/lab-stop.yml|${env_default_id}|${inv_localhost_id}"
        "Lab Status|ansible/playbooks/ops/lab-status.yml|${env_default_id}|${inv_localhost_id}"
        "PKI Health Check|ansible/playbooks/ops/pki-health.yml|${env_all_id}|${inv_localhost_id}"
        "Container Status|ansible/playbooks/ops/container-status.yml|${env_default_id}|${inv_localhost_id}"
        "DNS Check|ansible/playbooks/ops/dns-check.yml|${env_default_id}|${inv_localhost_id}"
        "Kafka Topics|ansible/playbooks/ops/kafka-topics.yml|${env_default_id}|${inv_localhost_id}"
        "Backup PKI|ansible/playbooks/ops/backup-pki.yml|${env_default_id}|${inv_localhost_id}"
        "Cleanup|ansible/playbooks/ops/cleanup.yml|${env_default_id}|${inv_localhost_id}"
    )

    # Declare associative array to capture template IDs for scheduling
    declare -A tmpl_ids

    for entry in "${ops_templates[@]}"; do
        IFS='|' read -r t_name t_playbook t_env t_inv <<< "$entry"
        tmpl_ids["$t_name"]=$(create_template "$project_id" "$t_name" "$t_playbook" "$t_env" "$t_inv" "$repo_id")
    done

    section "Task Templates - Certificate Management"

    local -a cert_templates=(
        "RSA: Issue Certificate|ansible/playbooks/dogtag-rsa-issue-certificate.yml|${env_rsa_id}|${inv_localhost_id}"
        "RSA: Revoke Certificate|ansible/playbooks/dogtag-rsa-revoke-certificate.yml|${env_rsa_id}|${inv_localhost_id}"
        "ECC: Issue Certificate|ansible/playbooks/dogtag-ecc-issue-certificate.yml|${env_ecc_id}|${inv_localhost_id}"
        "ECC: Revoke Certificate|ansible/playbooks/dogtag-ecc-revoke-certificate.yml|${env_ecc_id}|${inv_localhost_id}"
        "PQC: Issue Certificate|ansible/playbooks/dogtag-pqc-issue-certificate.yml|${env_pqc_id}|${inv_localhost_id}"
        "PQC: Revoke Certificate|ansible/playbooks/dogtag-pqc-revoke-certificate.yml|${env_pqc_id}|${inv_localhost_id}"
        "FreeIPA: Revoke Certificate|ansible/playbooks/freeipa-revoke-certificate.yml|${env_default_id}|${inv_localhost_id}"
    )

    for entry in "${cert_templates[@]}"; do
        IFS='|' read -r t_name t_playbook t_env t_inv <<< "$entry"
        create_template "$project_id" "$t_name" "$t_playbook" "$t_env" "$t_inv" "$repo_id"
    done

    section "Task Templates - Incident Response"

    local -a ir_templates=(
        "Incident Response: Full|ansible/playbooks/incident-response-full.yml|${env_ir_id}|${inv_localhost_id}"
        "Incident Response: Bulk|ansible/playbooks/incident-response-bulk.yml|${env_ir_id}|${inv_localhost_id}"
    )

    for entry in "${ir_templates[@]}"; do
        IFS='|' read -r t_name t_playbook t_env t_inv <<< "$entry"
        create_template "$project_id" "$t_name" "$t_playbook" "$t_env" "$t_inv" "$repo_id"
    done

    section "Task Templates - PKI Initialization"

    create_template "$project_id" \
        "Init PKI Hierarchy" \
        "ansible/playbooks/init-pki-hierarchy.yml" \
        "$env_all_id" \
        "$inv_pki_id" \
        "$repo_id"

    # 7. Create schedules
    section "Scheduled Tasks"

    local -a schedules=(
        "Lab Status|Lab Status - Every 5 min|*/5 * * * *"
        "PKI Health Check|PKI Health Check - Every 15 min|*/15 * * * *"
        "Container Status|Container Status - Every 10 min|*/10 * * * *"
        "DNS Check|DNS Check - Every 30 min|*/30 * * * *"
        "Cleanup|Cleanup - Weekly Sunday 3 AM|0 3 * * 0"
    )

    for entry in "${schedules[@]}"; do
        IFS='|' read -r s_template s_name s_cron <<< "$entry"
        local tid="${tmpl_ids[$s_template]}"
        if [[ -n "$tid" && "$tid" != "null" ]]; then
            create_schedule "$project_id" "$tid" "$s_name" "$s_cron"
        else
            error "Cannot schedule '${s_name}': template '${s_template}' not found"
        fi
    done

    # Summary
    echo "" >&2
    echo -e "${CYAN}============================================${NC}" >&2
    echo -e "${GREEN}  Semaphore setup complete!${NC}" >&2
    echo -e "${CYAN}============================================${NC}" >&2
    echo "" >&2
    echo -e "  Project:       ${PROJECT_NAME} (id=${project_id})" >&2
    echo -e "  Keys:          4 created" >&2
    echo -e "  Repository:    1 created" >&2
    echo -e "  Inventories:   2 created" >&2
    echo -e "  Environments:  6 created" >&2
    echo -e "  Templates:     20 created" >&2
    echo -e "  Schedules:     6 created" >&2
    echo "" >&2
    echo -e "  ${BLUE}Semaphore UI:${NC} ${SEMAPHORE_URL}" >&2
    echo "" >&2
}

main "$@"
