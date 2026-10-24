#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
  struct pam_response *r = calloc(n, sizeof *r);
  const char *typed = getenv("PAMSTACK_TYPED");
  (void)data;
  for (int i = 0; i < n; i++) {
    printf("PROMPT %d %s\n", msg[i]->msg_style, msg[i]->msg);
    if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON)
      r[i].resp = strdup(typed ? typed : "");
  }
  fflush(stdout);
  *resp = r;
  return PAM_SUCCESS;
}

int main(int argc, char **argv) {
  struct pam_conv c = {conv, NULL};
  pam_handle_t *h;
  if (argc < 3) return 2;
  if (pam_start(argv[1], argv[2], &c, &h) != PAM_SUCCESS) return 2;
  pam_set_item(h, PAM_TTY, ":0");
  pam_fail_delay(h, 0);
  int rc = pam_authenticate(h, 0);
  printf("AUTH %d\n", rc);
  if (rc == PAM_SUCCESS) printf("SETCRED %d\n", pam_setcred(h, PAM_ESTABLISH_CRED));
  pam_end(h, rc);
  return 0;
}
