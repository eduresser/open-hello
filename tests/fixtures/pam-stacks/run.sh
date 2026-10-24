#!/bin/sh
set -u
distro=$1
user=hello
password=Correct-Horse-7
src=/src/tests/fixtures/pam-stacks

secdir=$(dirname "$(ls /usr/lib64/security/pam_unix.so /usr/lib/*/security/pam_unix.so /usr/lib/security/pam_unix.so 2>/dev/null | head -n 1)")
cc -shared -fPIC -o "$secdir/pam_openhello.so" "$src/pam_openhello_stub.c" || exit 3
cc -shared -fPIC -o "$secdir/pam_kwallet5.so" "$src/pam_keyring_stub.c" || exit 3
cc -o /usr/local/bin/pamstack-client "$src/client.c" -lpam || exit 3
mkdir -p /run/pamstack /run/faillock

if [ "$distro" = opensuse ]; then
  pam-config -a --kwallet5 || exit 3
fi

/opt/openhello-cli pam enable > /run/pamstack/enable 2>&1
echo "ENABLE rc=$?"
sed 's/^/ENABLE| /' /run/pamstack/enable

show() {
  for f in "$@"; do
    for d in /etc/pam.d /usr/lib/pam.d; do
      if [ -e "$d/$f" ]; then
        echo "FILE $d/$f -> $(readlink -f "$d/$f")"
        grep -Ev '^[[:space:]]*(#|$)' "$d/$f" | sed 's/^/FILE| /'
        break
      fi
    done
  done
}

scenario() {
  name=$1 release=$2 typed=$3
  rm -f /run/pamstack/log /run/pamstack/release
  : > /run/pamstack/log
  [ "$release" != none ] && printf '%s\n' "$release" > /run/pamstack/release
  echo "SCENARIO $name"
  PAMSTACK_TYPED=$typed pamstack-client sddm "$user"
  sed 's/^/LOG /' /run/pamstack/log
  echo "END $name"
}

run_all() {
  scenario "$1:release" "$password" ""
  scenario "$1:wrong-token" "Stale-Password-1" "$password"
  scenario "$1:typed" none "$password"
}

case $distro in
  opensuse) show sddm common-auth common-auth-pc ;;
  fedora) show sddm password-auth system-auth postlogin ;;
  debian) show sddm common-auth ;;
  arch) show sddm system-login system-auth ;;
esac
run_all packaged

if [ "$distro" = fedora ]; then
  target=$(readlink -f /etc/pam.d/password-auth)
  sed -i '0,/^auth/s//auth        sufficient                                   pam_openhello.so\nauth/' "$target"
  show password-auth
  run_all manual-password-auth
fi
