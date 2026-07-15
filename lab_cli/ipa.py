"""FreeIPA operations — all commands run inside the freeipa container via podman exec."""

import subprocess
from typing import Optional

IPA_CONTAINER = "freeipa"
REALM = "CERT-LAB.LOCAL"
LDAP_BASE_DN = "dc=cert-lab,dc=local"
DEFAULT_PASSWORD = "RedHat123"


def ipa_exec(cmd: str, timeout: int = 30) -> tuple[int, str]:
    """Run a shell command inside the FreeIPA container."""
    result = subprocess.run(
        ["sudo", "podman", "exec", IPA_CONTAINER, "bash", "-c", cmd],
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, (result.stdout + result.stderr).strip()


def ipa_is_running() -> bool:
    try:
        result = subprocess.run(
            ["sudo", "podman", "inspect", "--format", "{{.State.Status}}", IPA_CONTAINER],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0 and result.stdout.strip() == "running"
    except Exception:
        return False


def ipa_kinit(principal: str = "admin", password: str = DEFAULT_PASSWORD) -> bool:
    rc, _ = ipa_exec(f"echo '{password}' | kinit {principal}@{REALM} 2>/dev/null")
    return rc == 0


def ipa_user_exists(username: str) -> bool:
    rc, _ = ipa_exec(f"echo '{DEFAULT_PASSWORD}' | kinit admin 2>/dev/null && ipa user-show {username} >/dev/null 2>&1")
    return rc == 0


def ipa_user_add(username: str, password: str = DEFAULT_PASSWORD) -> tuple[bool, str]:
    """Create a FreeIPA user and set their password. Returns (success, status_msg)."""
    if ipa_user_exists(username):
        return True, "exists"

    first_name = username.replace("-", " ").title().split()[0]
    script = f"""
echo '{DEFAULT_PASSWORD}' | kinit admin 2>/dev/null
ipa user-add {username} --first='{first_name}' --last=Test --random >/dev/null 2>&1
ldappasswd -x -H ldap://localhost:389 -D "cn=Directory Manager" \
    -w '{DEFAULT_PASSWORD}' -s '{password}' \
    "uid={username},cn=users,cn=accounts,{LDAP_BASE_DN}" 2>/dev/null
echo 'OK'
"""
    rc, out = ipa_exec(script)
    if "OK" in out:
        return True, "created"
    return False, f"failed: {out[:100]}"


def ipa_user_list() -> list[dict]:
    """List FreeIPA users. Returns list of {login, name, principal}."""
    ipa_kinit()
    rc, out = ipa_exec("ipa user-find --pkey-only --sizelimit=100 2>/dev/null | grep 'User login:' | awk '{print $NF}'")
    if rc != 0 or not out.strip():
        return []

    users = []
    for login in out.strip().splitlines():
        login = login.strip()
        if not login or login in ("admin",):
            continue
        users.append({
            "login": login,
            "name": f"{login.replace('-', ' ').title()}",
            "principal": f"{login}@{REALM}",
        })
    return users


def ipa_host_add(hostname: str) -> bool:
    ipa_kinit()
    rc, _ = ipa_exec(f"ipa host-add {hostname} --force 2>/dev/null || true")
    return True


def ipa_service_add(service: str) -> bool:
    ipa_kinit()
    rc, _ = ipa_exec(f"ipa service-add {service} --force 2>/dev/null || true")
    return True


def ipa_get_keytab(service: str, keytab_path: str) -> bool:
    """Extract a keytab for a service principal."""
    ipa_kinit()
    rc, out = ipa_exec(
        f"ipa-getkeytab -s ipa.cert-lab.local -p {service} -k {keytab_path} && "
        f"chmod 644 {keytab_path}"
    )
    return rc == 0


def ipa_gateway_ip() -> str:
    """Get the host gateway IP from the FreeIPA container's network."""
    try:
        result = subprocess.run(
            ["sudo", "podman", "inspect", "--format",
             "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", IPA_CONTAINER],
            capture_output=True, text=True, timeout=5,
        )
        gw = result.stdout.strip()[:15]
        return gw if gw else "172.25.0.1"
    except Exception:
        return "172.25.0.1"
