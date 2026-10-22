#!/usr/bin/env bash
# Spike T-014 (credential-login-v1b): ASM-010, ASM-006, ASM-007 on a software TPM.
# Throwaway proof of concept. Never touches /dev/tpm0, never needs root.
# Fetches openSUSE RPMs with `zypper download` (user space) and unpacks them into a private prefix.
# Idempotent: re-running reuses the cache and rebuilds all TPM state from scratch.
set -uo pipefail

WORK="${OPENHELLO_SPIKE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/openhello-spike}"
ROOT="$WORK/root"
RPMS="$WORK/rpm"
BIN="$WORK/bin"
RUN="$WORK/run"
PACKAGES=(
  tpm2-pkcs11 pam_pkcs11 pam_wrapper pam-devel python3-tpm2-pytss
  python313-pyasn1 python313-pyasn1-modules python313-asn1crypto
  libtss2-policy0 libtss2-tcti-swtpm0 libtss2-tcti-spi-helper0 libtss2-tcti-tabrmd0
  tpm2.0-abrmd mozilla-nss-tools
)
FAILS=0
PIDS=()

say() { printf '%s\n' "$*"; }
ok() { say "  PASS  $*"; }
bad() { say "  FAIL  $*"; FAILS=$((FAILS + 1)); }
check() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
quiet_fapi() { grep -v -iE 'fapi|Please see https://github.com/tpm2-software' || true; }

need() { command -v "$1" >/dev/null || { say "missing prerequisite: $1"; exit 2; }; }
for t in swtpm tpm2_createprimary tpm2_dictionarylockout zypper rpm2cpio cpio gcc openssl xxd python3 dbus-daemon; do need "$t"; done
[ -e /usr/include/p11-kit-1/p11-kit/pkcs11.h ] || { say "missing p11-kit-devel headers"; exit 2; }
LIBPAM=$(ls /usr/lib64/libpam.so.0 /lib64/libpam.so.0 /usr/lib/libpam.so.0 2>/dev/null | head -1)
[ -n "$LIBPAM" ] || { say "libpam.so.0 not found"; exit 2; }

cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

free_port_pair() {
  python3 - <<'PY'
import socket
while True:
    a = socket.socket(); a.bind(("127.0.0.1", 0)); p = a.getsockname()[1]
    b = socket.socket()
    try:
        b.bind(("127.0.0.1", p + 1)); print(p); break
    except OSError:
        continue
PY
}

start_swtpm() {
  local dir=$1 port=$2
  rm -rf "$dir"; mkdir -p "$dir"
  swtpm socket --tpm2 --tpmstate "dir=$dir" --server "type=tcp,port=$port" \
    --ctrl "type=tcp,port=$((port + 1))" --flags not-need-init,startup-clear >"$dir/swtpm.log" 2>&1 &
  PIDS+=($!)
  sleep 1
}

mkdir -p "$WORK" "$RPMS" "$BIN" "$ROOT"
say "== setup: user-space packages in $WORK"
if [ ! -e "$ROOT/.extracted" ]; then
  zypper --no-refresh --pkg-cache-dir="$RPMS" download "${PACKAGES[@]}" >"$WORK/zypper.log" 2>&1 || true
  for pkg in "${PACKAGES[@]}"; do
    f=$(ls "$RPMS"/repo-*/*/"$pkg"-[0-9]*.rpm 2>/dev/null | head -1)
    [ -n "$f" ] || { say "package not downloaded: $pkg (see $WORK/zypper.log)"; exit 2; }
    (cd "$ROOT" && rpm2cpio "$f" | cpio -idm --quiet)
  done
  touch "$ROOT/.extracted"
fi

TCTI_LIB="$ROOT/usr/lib64/libtss2-tcti-swtpm.so.0"
export LD_LIBRARY_PATH="$ROOT/usr/lib64" PYTHONWARNINGS=ignore
PTOOL="python3 $ROOT/usr/bin/tpm2_ptool"
P11_REAL="$ROOT/usr/lib64/pkcs11/libtpm2_pkcs11.so.0.0.0"
PAMMOD="$ROOT/usr/lib64/security/pam_pkcs11.so"
export PYTHONPATH="$ROOT/usr/lib/python3.13/site-packages:$ROOT/usr/lib64/python3.13/site-packages"

say "== build test helpers"
mkdir -p "$WORK/src"
cat >"$WORK/src/p11probe.c" <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <p11-kit/pkcs11.h>

static void hex(const unsigned char *b, unsigned long n) { for (unsigned long i = 0; i < n; i++) printf("%02x", b[i]); }

int main(int argc, char **argv) {
  if (argc < 3) { fprintf(stderr, "usage: p11probe MODULE info|pubkey|sign [PIN]\n"); return 2; }
  void *h = dlopen(argv[1], RTLD_NOW);
  if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
  CK_C_GetFunctionList gfl = (CK_C_GetFunctionList)dlsym(h, "C_GetFunctionList");
  CK_FUNCTION_LIST_PTR f;
  if (!gfl || gfl(&f) != CKR_OK) return 1;
  if (f->C_Initialize(NULL) != CKR_OK) return 1;
  CK_SLOT_ID slots[8]; CK_ULONG ns = 8;
  if (f->C_GetSlotList(CK_TRUE, slots, &ns) != CKR_OK || ns == 0) { fprintf(stderr, "no token\n"); return 1; }
  CK_SLOT_ID slot = slots[0];
  const char *want = getenv("P11PROBE_LABEL");
  for (CK_ULONG i = 0; want && i < ns; i++) {
    CK_TOKEN_INFO t; f->C_GetTokenInfo(slots[i], &t);
    if (!strncmp((char *)t.label, want, strlen(want))) slot = slots[i];
  }
  CK_TOKEN_INFO ti; f->C_GetTokenInfo(slot, &ti);
  CK_SESSION_HANDLE s;
  if (f->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &s) != CKR_OK) return 1;
  if (!strcmp(argv[2], "info")) {
    printf("label=%.32s login_required=%d\n", ti.label, !!(ti.flags & CKF_LOGIN_REQUIRED));
    return 0;
  }
  CK_OBJECT_CLASS cls = !strcmp(argv[2], "pubkey") ? CKO_PUBLIC_KEY : CKO_PRIVATE_KEY;
  CK_KEY_TYPE kt = CKK_EC;
  CK_ATTRIBUTE t[] = {{CKA_CLASS, &cls, sizeof cls}, {CKA_KEY_TYPE, &kt, sizeof kt}};
  if (cls == CKO_PRIVATE_KEY && argc > 3) {
    CK_RV rv = f->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)argv[3], strlen(argv[3]));
    if (rv != CKR_OK) { printf("login_rv=0x%lx\n", rv); return 3; }
  }
  f->C_FindObjectsInit(s, t, 2);
  CK_OBJECT_HANDLE o; CK_ULONG n = 0;
  f->C_FindObjects(s, &o, 1, &n);
  f->C_FindObjectsFinal(s);
  if (!n) { fprintf(stderr, "no EC object\n"); return 1; }
  if (cls == CKO_PUBLIC_KEY) {
    unsigned char pt[256], pr[64];
    CK_ATTRIBUTE a[] = {{CKA_EC_POINT, pt, sizeof pt}, {CKA_EC_PARAMS, pr, sizeof pr}};
    if (f->C_GetAttributeValue(s, o, a, 2) != CKR_OK) return 1;
    printf("params="); hex(pr, a[1].ulValueLen); printf("\npoint="); hex(pt, a[0].ulValueLen); printf("\n");
    return 0;
  }
  CK_MECHANISM m = {CKM_ECDSA, NULL, 0};
  unsigned char d[32] = {1, 2, 3}, sig[128]; CK_ULONG sl = sizeof sig;
  CK_RV rv = f->C_SignInit(s, &m, o);
  if (rv == CKR_OK) rv = f->C_Sign(s, d, sizeof d, sig, &sl);
  printf("sign_rv=0x%lx siglen=%lu\n", rv, sl);
  return rv == CKR_OK ? 0 : 4;
}
EOF
cat >"$WORK/src/p11wrap.c" <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <p11-kit/pkcs11.h>

static CK_FUNCTION_LIST real;
static CK_FUNCTION_LIST wrapped;
static int loaded;

static CK_RV C_Login_override(CK_SESSION_HANDLE s, CK_USER_TYPE t, CK_UTF8CHAR_PTR pin, CK_ULONG len) {
  (void)pin;
  if (getenv("OPENHELLO_SPIKE_TRACE")) fprintf(stderr, "[p11wrap] C_Login called pin=%p len=%lu\n", (void *)pin, len);
  const char *ticket = getenv("OPENHELLO_SPIKE_TICKET");
  const char *secret = getenv("OPENHELLO_SPIKE_SECRET");
  if (!ticket || access(ticket, F_OK) != 0 || !secret) return CKR_PIN_INCORRECT;
  unlink(ticket);
  return real.C_Login(s, t, (CK_UTF8CHAR_PTR)secret, strlen(secret));
}

static CK_RV C_GetTokenInfo_override(CK_SLOT_ID id, CK_TOKEN_INFO_PTR info) {
  CK_RV rv = real.C_GetTokenInfo(id, info);
  if (rv == CKR_OK && getenv("OPENHELLO_SPIKE_PAP")) info->flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
  return rv;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
  if (!loaded) {
    const char *path = getenv("OPENHELLO_REAL_PKCS11");
    void *h = path ? dlopen(path, RTLD_NOW | RTLD_LOCAL) : NULL;
    if (!h) return CKR_GENERAL_ERROR;
    CK_C_GetFunctionList gfl = (CK_C_GetFunctionList)dlsym(h, "C_GetFunctionList");
    CK_FUNCTION_LIST_PTR r;
    if (!gfl || gfl(&r) != CKR_OK) return CKR_GENERAL_ERROR;
    real = *r;
    wrapped = real;
    wrapped.C_Login = C_Login_override;
    wrapped.C_GetTokenInfo = C_GetTokenInfo_override;
    loaded = 1;
  }
  *out = &wrapped;
  return CKR_OK;
}
EOF
cat >"$WORK/src/pamtest.c" <<'EOF'
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
  (void)data;
  struct pam_response *r = calloc(n, sizeof *r);
  for (int i = 0; i < n; i++) {
    int secret = msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON;
    fprintf(stderr, "[pamtest] conv style=%d msg=\"%s\"\n", msg[i]->msg_style, msg[i]->msg);
    if (secret) r[i].resp = strdup(getenv("PAMTEST_PIN") ? getenv("PAMTEST_PIN") : "");
  }
  *resp = r;
  return PAM_SUCCESS;
}

int main(int argc, char **argv) {
  if (argc < 3) { fprintf(stderr, "usage: pamtest SERVICE USER\n"); return 2; }
  struct pam_conv c = {conv, NULL};
  pam_handle_t *h;
  int rc = pam_start(argv[1], argv[2], &c, &h);
  if (rc == PAM_SUCCESS) rc = pam_authenticate(h, 0);
  printf("pam_authenticate=%d (%s)\n", rc, pam_strerror(h, rc));
  pam_end(h, rc);
  return rc == PAM_SUCCESS ? 0 : 1;
}
EOF
gcc -Wall -o "$BIN/p11probe" "$WORK/src/p11probe.c" -I/usr/include/p11-kit-1 -ldl \
  && gcc -Wall -shared -fPIC -o "$BIN/libopenhello_p11wrap.so" "$WORK/src/p11wrap.c" -I/usr/include/p11-kit-1 -ldl \
  && gcc -Wall -o "$BIN/pamtest" "$WORK/src/pamtest.c" -I"$ROOT/usr/include" "$LIBPAM" \
  || { say "helper build failed"; exit 2; }

say
say "== ASM-010: swtpm ECC P-256 and dictionary-attack lockout (direct TCTI, no resource manager)"
PORT=$(free_port_pair)
start_swtpm "$RUN/swtpm-direct" "$PORT"
export TPM2TOOLS_TCTI="$TCTI_LIB:port=$PORT"
A="$RUN/a"; rm -rf "$A"; mkdir -p "$A"
flush() { tpm2_flushcontext -t >/dev/null 2>&1; }
counter() { tpm2_getcap properties-variable 2>/dev/null | sed -n 's/^TPM2_PT_LOCKOUT_COUNTER: //p'; }
in_lockout() { tpm2_getcap properties-variable 2>/dev/null | sed -n 's/^ *inLockout: *//p'; }
(
  cd "$A" || exit 1
  tpm2_getcap ecc-curves 2>/dev/null | grep -q 'TPM2_ECC_NIST_P256' && echo "curve TPM2_ECC_NIST_P256 listed"
  tpm2_createprimary -C o -G ecc256 -c p.ctx >/dev/null && flush
  tpm2_create -C p.ctx -G ecc256:ecdsa-sha256 -u k.pub -r k.priv -p keypw >/dev/null && flush
  tpm2_load -C p.ctx -u k.pub -r k.priv -c k.ctx >/dev/null && flush
  echo hello >m
  tpm2_sign -c k.ctx -g sha256 -s ecdsa -p keypw -o sig m && flush
  tpm2_verifysignature -c k.ctx -g sha256 -s sig -m m >/dev/null && echo "TPM ECDSA signature verified" && flush
) >"$A/log" 2>&1
check "ECC P-256 key created, loaded, signs and verifies inside swtpm" grep -q 'TPM ECDSA signature verified' "$A/log"
tpm2_dictionarylockout --setup-parameters --max-tries=3 --recovery-time=3600 --lockout-recovery-time=3600 >/dev/null 2>&1; flush
(cd "$A" && for i in 1 2 3; do tpm2_sign -c k.ctx -g sha256 -s ecdsa -p wrong -o s2 m >/dev/null 2>"$A/wrong$i"; flush; done)
say "  lockout counter after 3 wrong auth values: $(counter), inLockout=$(in_lockout)"
check "3 wrong auth values report 'DA counter incremented'" grep -q 'DA counter incremented' "$A/wrong1"
check "TPM enters DA lockout after max-tries" test "$(in_lockout)" = 1
(cd "$A" && tpm2_sign -c k.ctx -g sha256 -s ecdsa -p keypw -o s3 m 2>"$A/locked"); flush
check "correct auth value is refused while locked out (TPM_RC_LOCKOUT 0x921)" grep -q '0x921' "$A/locked"
tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1; flush
check "lockout cleared by lockoutAuth, correct auth value works again" bash -c "cd $A && tpm2_sign -c k.ctx -g sha256 -s ecdsa -p keypw -o s4 m >/dev/null 2>&1"
flush

say
say "== ASM-006: tpm2-pkcs11 P-256 token + pam_pkcs11 (private D-Bus, abrmd, second swtpm)"
PORT2=$(free_port_pair)
start_swtpm "$RUN/swtpm-token" "$PORT2"
mkdir -p "$RUN"
dbus-daemon --session --nofork --print-address >"$RUN/dbus.addr" 2>/dev/null &
PIDS+=($!)
sleep 1
export DBUS_SESSION_BUS_ADDRESS=$(head -1 "$RUN/dbus.addr")
"$ROOT/usr/sbin/tpm2-abrmd" --session --tcti="$TCTI_LIB:port=$PORT2" >"$RUN/abrmd.log" 2>&1 &
PIDS+=($!)
sleep 2
export TPM2TOOLS_TCTI=tabrmd:bus_type=session TPM2_PKCS11_TCTI=tabrmd:bus_type=session
export TPM2_PKCS11_STORE="$RUN/store"
rm -rf "$TPM2_PKCS11_STORE"; mkdir -p "$TPM2_PKCS11_STORE"
G="$RUN/g"; rm -rf "$G"; mkdir -p "$G"; cd "$G" || exit 1
$PTOOL init >/dev/null 2>&1
$PTOOL addtoken --pid 1 --sopin sosopin --userpin 1234 --label oh >/dev/null 2>&1
$PTOOL addkey --label oh --userpin 1234 --algorithm ecc256 >/dev/null 2>&1
"$BIN/p11probe" "$P11_REAL" info 2>/dev/null | tee info.txt
check "token 'oh' visible through the PKCS#11 module, login required" grep -q 'label=oh .*login_required=1' info.txt
"$BIN/p11probe" "$P11_REAL" pubkey 2>/dev/null >pub.txt
check "public key is EC with params prime256v1 (06082a8648ce3d030107)" grep -q '^params=06082a8648ce3d030107$' pub.txt
check "ECDSA signature through C_Login(1234) + C_Sign succeeds" bash -c "'$BIN/p11probe' '$P11_REAL' sign 1234 2>/dev/null | grep -q 'sign_rv=0x0'"
check "wrong PIN is rejected with CKR_PIN_INCORRECT (0xa0)" bash -c "'$BIN/p11probe' '$P11_REAL' sign 0000 2>/dev/null | grep -q 'login_rv=0xa0'"
say "  TPM lockout counter after one wrong PKCS#11 PIN: $(counter)"
check "wrong PIN increments the TPM dictionary-attack counter" test "$(( $(counter) ))" -ge 1
tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1

P=$(sed -n 's/^point=0441//p' pub.txt)
(printf '3059301306072a8648ce3d020106082a8648ce3d030107034200'; printf '%s' "$P") | xxd -r -p >spki.der
openssl pkey -pubin -inform DER -in spki.der -out pub.pem
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -subj "/CN=openhello-spike-ca" -days 30 2>/dev/null
openssl req -new -key ca.key -subj "/CN=$(id -un)-spike" -out leaf.csr 2>/dev/null
openssl x509 -req -in leaf.csr -force_pubkey pub.pem -CA ca.pem -CAkey ca.key -CAcreateserial -out leaf.pem -days 30 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out other.key 2>/dev/null
openssl pkey -in other.key -pubout -out other.pub
openssl x509 -req -in leaf.csr -force_pubkey other.pub -CA ca.pem -CAkey ca.key -CAcreateserial -out leaf_bad.pem -days 30 2>/dev/null
KID=$($PTOOL listobjects --label oh 2>/dev/null | grep -m1 -A1 'CKA_ID:' | grep -o '[0-9a-f]\{16,\}')
cert_id() { $PTOOL listobjects --label oh 2>/dev/null | awk '/CKO_CERTIFICATE/{f=1} f&&/id:/{print $2; exit}'; }

mkdir -p nssdb cacerts crls pamd
"$ROOT/usr/bin/certutil" -N -d "sql:$G/nssdb" --empty-password >/dev/null 2>&1
"$ROOT/usr/bin/certutil" -A -d "sql:$G/nssdb" -n spike-ca -t "CT,C,C" -i ca.pem >/dev/null 2>&1
echo "CN=$(id -un)-spike -> $(id -un)" >subject_mapping
write_conf() { # name module policy
  cat >"$1" <<EOF
pam_pkcs11 {
  nullok = false;
  debug = false;
  use_first_pass = false; try_first_pass = false; use_authtok = false;
  card_only = false; wait_for_card = false;
  use_pkcs11_module = tpm2;
  pkcs11_module tpm2 {
    module = $2;
    description = "tpm2-pkcs11";
    slot_num = 0;
    nss_dir = $G/nssdb;
    support_threads = false;
    ca_dir = $G/cacerts;
    crl_dir = $G/crls;
    cert_policy = $3;
  }
  use_mappers = subject;
  mapper_search_path = $ROOT/usr/lib64/pam_pkcs11;
  mapper subject { debug = false; module = internal; ignorecase = false; mapfile = file://$G/subject_mapping; }
}
EOF
}
write_conf pam_real.conf "$P11_REAL" signature
write_conf pam_real_ca.conf "$P11_REAL" ca,signature
write_conf pam_wrap.conf "$BIN/libopenhello_p11wrap.so" signature
for svc in real real_ca wrap; do echo "auth required $PAMMOD config_file=$G/pam_$svc.conf" >"pamd/oh$svc"; done
pam() { # service, then env assignments via caller
  env PAM_WRAPPER=1 PAM_WRAPPER_SERVICE_DIR="$G/pamd" LD_PRELOAD="$ROOT/usr/lib64/libpam_wrapper.so" \
    "$BIN/pamtest" "$1" "$(id -un)" 2>&1 | grep -E '^\[pamtest\]|^\[p11wrap\]|^pam_authenticate'
}

$PTOOL addcert --label oh --key-id "$KID" leaf_bad.pem >/dev/null 2>&1
BADID=$(cert_id)
PAMTEST_PIN=1234 pam ohreal >neg.txt
check "NEGATIVE CONTROL: cert for a different key fails the signature check (Error 2342)" grep -q 'Verifying signature failed' neg.txt
$PTOOL objdel "$BADID" >/dev/null 2>&1
$PTOOL addcert --label oh --key-id "$KID" leaf.pem >/dev/null 2>&1
PAMTEST_PIN=1234 pam ohreal >pos.txt
check "pam_pkcs11 (cert_policy=signature) authenticates with the P-256 TPM key" grep -q 'pam_authenticate=0 ' pos.txt
PAMTEST_PIN=1234 pam ohreal_ca >pos_ca.txt
check "pam_pkcs11 (cert_policy=ca,signature) authenticates, CA chain checked by NSS" grep -q 'pam_authenticate=0 ' pos_ca.txt
PAMTEST_PIN=9999 pam ohreal >wrongpin.txt
check "pam_pkcs11 with wrong PIN fails (Error 2320)" grep -q 'Wrong smart card PIN' wrongpin.txt
tpm2_dictionarylockout --clear-lockout >/dev/null 2>&1
PAMTEST_PIN= pam ohreal >emptypin.txt
check "pam_pkcs11 rejects an empty PIN before C_Login (Error 2318)" grep -q 'Empty smart card PIN' emptypin.txt
say "  PAM prompts seen: $(grep -c 'style=1' pos.txt) secret prompt(s): $(grep 'style=1' pos.txt | head -1)"

say
say "== ASM-007: wrapper PKCS#11 module replaces only C_Login (PIN swapped for a secret after a ticket check)"
export OPENHELLO_REAL_PKCS11="$P11_REAL" OPENHELLO_SPIKE_SECRET=1234 OPENHELLO_SPIKE_TICKET="$G/ticket" OPENHELLO_SPIKE_TRACE=1
rm -f "$G/ticket"
PAMTEST_PIN=placeholder pam ohwrap >w_noticket.txt
check "no ticket: wrapper refuses, PAM fails even though the real secret is known" grep -q 'Wrong smart card PIN' w_noticket.txt
touch "$G/ticket"
PAMTEST_PIN=placeholder pam ohwrap >w_ticket.txt
check "ticket present: placeholder PIN from PAM is swapped, pam_pkcs11 authenticates" grep -q 'pam_authenticate=0 ' w_ticket.txt
check "wrapper C_Login was called (swap happened inside the wrapper, not by PAM)" grep -q 'C_Login called' w_ticket.txt
check "ticket is consumed (single use)" test ! -e "$G/ticket"
PAMTEST_PIN=placeholder pam ohwrap >w_reuse.txt
check "second attempt without a new ticket fails" grep -q 'Wrong smart card PIN' w_reuse.txt
touch "$G/ticket"
OPENHELLO_SPIKE_PAP=1 PAMTEST_PIN=placeholder pam ohwrap >w_pap.txt
if grep -q 'pam_authenticate=0 ' w_pap.txt; then
  say "  INFO  PROTECTED_AUTHENTICATION_PATH shortcut works"
else
  say "  INFO  PROTECTED_AUTHENTICATION_PATH shortcut does NOT work in this pam_pkcs11 (C_Login never reached); PAM must answer a non-empty placeholder PIN"
fi
unset OPENHELLO_SPIKE_PAP OPENHELLO_SPIKE_TRACE
rm -f "$G/ticket"

say
say "== design check: 20 random bytes as hex PIN (40 chars) through the real module"
HEXPIN=$(head -c 20 /dev/urandom | xxd -p)
$PTOOL addtoken --pid 1 --sopin sosopin --userpin "$HEXPIN" --label ohhex >/dev/null 2>&1
$PTOOL addkey --label ohhex --userpin "$HEXPIN" --algorithm ecc256 >/dev/null 2>&1
check "40-char hex PIN works as C_Login secret for a P-256 key" bash -c "P11PROBE_LABEL=ohhex '$BIN/p11probe' '$P11_REAL' sign '$HEXPIN' 2>/dev/null | grep -q 'sign_rv=0x0'"

say
say "== not covered here: real /dev/tpm0 behavior, a real screen locker conversation"
if [ "$FAILS" -eq 0 ]; then say "RESULT: all checks passed"; else say "RESULT: $FAILS check(s) failed"; fi
exit "$FAILS"
