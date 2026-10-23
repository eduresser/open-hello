#!/usr/bin/env bash
# Run as root on a minimal system right after installing the openhello package; exits 1 listing every runtime need the package did not pull in.
set -euo pipefail

TOOLS=(tpm2_createprimary tpm2_create tpm2_load tpm2_unseal tpm2_getcap tpm2_flushcontext tpm2_dictionarylockout
  tpm2_ptool p11-kit python3 pkttyagent dbus-daemon systemctl)

problems=()
problem() { problems+=("$1"); }

package_files() {
  if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W openhello >/dev/null 2>&1; then dpkg-query -L openhello
  elif command -v rpm >/dev/null 2>&1 && rpm -q openhello >/dev/null 2>&1; then rpm -ql openhello
  elif command -v pacman >/dev/null 2>&1 && pacman -Q openhello >/dev/null 2>&1; then pacman -Qlq openhello
  else echo "openhello package is not installed" >&2; exit 2
  fi
}

is_elf() { [ -f "$1" ] && [ "$(head -c 4 "$1" | od -An -c | tr -d ' ')" = '177ELF' ]; }

known_sonames="$(ldconfig -p | sed -nE 's/^[[:space:]]+([^[:space:]]+) .*/\1/p' | sort -u)"

resolves() {
  local candidate="$1" rest
  while true; do
    grep -qxF "$candidate" <<<"$known_sonames" && return 0
    [ -e "/usr/lib/openhello/$candidate" ] && return 0
    rest="${candidate:3}"
    [[ "$rest" == *lib* ]] || return 1
    candidate="lib${rest#*lib}"
  done
}

check_elf() {
  local file="$1" missing soname
  missing="$(LD_LIBRARY_PATH=/usr/lib/openhello ldd "$file" 2>&1 | sed -nE 's/^[[:space:]]*([^[:space:]]+) => not found.*/\1/p' || true)"
  for soname in $missing; do problem "$file links $soname, which is not installed"; done
  for soname in $(grep -aoE 'lib[A-Za-z0-9_+-]+\.so\.[0-9]+' "$file" | sort -u); do
    resolves "$soname" || problem "$file loads $soname at run time, which is not installed"
  done
}

while IFS= read -r path; do
  if is_elf "$path"; then check_elf "$path"; fi
done < <(package_files)

for tool in "${TOOLS[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || problem "command $tool is not installed"
done
python3 -c 'import tpm2_pkcs11' >/dev/null 2>&1 || problem "python3 cannot import tpm2_pkcs11"
p11-kit list-modules 2>/dev/null | grep -q 'libtpm2_pkcs11\.so' || grep -q 'libtpm2_pkcs11\.so' <<<"$(ldconfig -p)" \
  || find /usr/lib /usr/lib64 -name 'libtpm2_pkcs11.so*' 2>/dev/null | grep -q . || problem "PKCS#11 module libtpm2_pkcs11.so is not installed"
[ -x /usr/lib/polkit-1/polkitd ] || [ -x /usr/libexec/polkit-1/polkitd ] || [ -x /usr/libexec/polkitd ] || [ -x /usr/lib/policykit-1/polkitd ] || command -v polkitd >/dev/null 2>&1 \
  || problem "polkitd is not installed"
openhello-cli pam status >/dev/null 2>&1 || problem "openhello-cli does not run"

if [ "${#problems[@]}" -gt 0 ]; then
  printf 'missing runtime dependencies:\n' >&2
  printf '  - %s\n' "${problems[@]}" >&2
  exit 1
fi
echo "all runtime dependencies of openhello are installed"
