#include <security/pam_modules.h>
#include <stdio.h>
#include <string.h>

#define RELEASE_PATH "/run/pamstack/release"
#define LOG_PATH "/run/pamstack/log"

static void record(pam_handle_t *h, const char *phase) {
  const void *token = NULL;
  pam_get_item(h, PAM_AUTHTOK, &token);
  FILE *f = fopen(LOG_PATH, "a");
  if (!f) return;
  fprintf(f, "OPENHELLO %s authtok=%s\n", phase, token ? (const char *)token : "(unset)");
  fclose(f);
}

int pam_sm_authenticate(pam_handle_t *h, int flags, int argc, const char **argv) {
  char secret[256];
  (void)flags; (void)argc; (void)argv;
  FILE *f = fopen(RELEASE_PATH, "r");
  if (f) {
    if (fgets(secret, sizeof secret, f)) {
      secret[strcspn(secret, "\n")] = 0;
      pam_set_item(h, PAM_AUTHTOK, secret);
    }
    fclose(f);
  }
  record(h, "authenticate");
  return PAM_IGNORE;
}

int pam_sm_setcred(pam_handle_t *h, int flags, int argc, const char **argv) {
  (void)flags; (void)argc; (void)argv;
  record(h, "setcred");
  return PAM_IGNORE;
}
