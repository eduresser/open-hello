# Guia de verificação da tela de bloqueio

open-hello não tem código por distro ou desktop: qualquer locker que autentique por PAM usa o mesmo módulo. Este guia mede o que é comum entre ambientes e registra o resultado de cada VM.

Provas automáticas (tag `@covers:AC-028-pam-path`, sem privilégio, `crates/openhello-cli/tests/pam_sudo.rs`): serviço `openhello-lockscreen` e gate do nível B. Elas não substituem o desbloqueio real; AC-028 e ASM-011 só fecham com a verificação manual.

## O que todos os lockers compartilham

- Chamam `pam_authenticate` com uma conversa PAM e um nome de serviço próprio.
- A maioria roda como o usuário (por isso o proxy PKCS#11 da T-025 dispensa root).
- A maioria dos serviços inclui o stack comum da distro: `common-auth` (Debian, Ubuntu, openSUSE) ou `system-auth` (Fedora, RHEL, Arch). Medido nesta máquina (openSUSE): `sudo`, `su`, `polkit-1`, `kde`, `xscreensaver` incluem `common-auth`; `sddm`, `login`, `sshd` usam `substack common-auth`.
- Mensagens Info da conversa podem ou não ser exibidas pelo locker (não verificado fora do KDE).

## Dois níveis de integração

**Nível A, por serviço (recomendado).** Inclua o stack empacotado no serviço desejado, antes do módulo de senha.

- `sudo`: `install.sh` faz `auth include sudo-openhello` (com backup `.openhello.bak`).
- KDE Plasma 6.8: `install.sh` cria `kde-face` com `auth include openhello-lockscreen`. O `kscreenlocker_greet` (6.8.0) tem um autenticador não interativo "Face" que usa o serviço `kde-face`; sem o arquivo ele registra "PAM service is not available". `kde-smartcard` não serve: espera cartão (`wait_for_card card_only`). O serviço `kde` (senha) não é alterado.
- Outros lockers (não verificados): no serviço do locker (`gdm-password`, `swaylock`, `i3lock`, `xscreensaver`, `lightdm`, `cinnamon-screensaver`, `mate-screensaver`) adicione as três primeiras linhas de `packaging/pam/openhello-lockscreen` antes da linha de senha. Não use o `include` do arquivo inteiro nesses: o `pam_deny` final encerraria a pilha antes da senha.

**Nível B, no stack comum (opcional, cobre todos os desktops).** Cole `/usr/share/openhello/pam/openhello-common-auth` acima da primeira linha `auth` do `common-auth`/`system-auth` e liste os serviços em `/etc/openhello/allowed-services` (um por linha, `#` comenta).

- O `pam_openhello` devolve `PAM_IGNORE` imediatamente quando: `PAM_RHOST` está definido ou há `SSH_CONNECTION` (ssh); não há `PAM_TTY` nem `DISPLAY`/`WAYLAND_DISPLAY` (cron, serviços); o serviço não está na lista; a lista falta ou não é de root (como root).
- Riscos: o stack comum afeta login, SSH, `su`, polkit e cron. Um erro nele pode bloquear tudo; o rosto aceito vale para qualquer serviço listado. Mantenha um TTY root aberto e backup do arquivo. Comece só com a lista `sudo`.
- Reversão: remova as três linhas e restaure o backup.

PIN não é suportado nas telas de bloqueio não interativas (sem campo de texto).

## Levantamento por VM

Em cada VM, sem sudo: `scripts/pam-survey.sh` (grava `pam-survey-<host>.md` no diretório atual; só lê). Cole a saída no registro. Ele lista distro, desktop e sessão, lockers, diretórios e serviços PAM com o stack que incluem, pam_pkcs11, tpm2-pkcs11, certutil, tpm2-abrmd, `/dev/tpmrm0`, nós V4L2 com GREY, systemd e serviços open-hello. Compare as seções entre VMs; as linhas `includes` mostram o nível A/B viável.

## Primeiro caminho: KDE Plasma desta máquina

1. Segurança: abra um TTY (Ctrl+Alt+F3) logado e um `sudo -s`; mantenha ambos até o fim.
2. `sudo scripts/install.sh --no-deps`.
3. `systemctl status openhello-keyd openhellod` e `ls -l /etc/pam.d/kde-face /etc/pam.d/openhello-lockscreen`.
4. Trave a tela (Meta+L) e olhe para a câmera IR.
5. Esperado: "Looking for your face..." e desbloqueio sem senha. Com outro rosto ou sem olhar, a senha segue funcionando.
6. Falha: `sudo systemctl stop openhellod`, trave de novo; a senha deve funcionar em poucos segundos.

Logs: `journalctl -b -t kscreenlocker_greet | grep -i -E "pam|authenticator"`; `journalctl -b -u openhellod -u openhello-keyd`; `sudo journalctl -b | grep -i -E "pam_openhello|pam_pkcs11"`.

Reversão: `sudo rm /etc/pam.d/kde-face /etc/pam.d/openhello-lockscreen`; `sudo`: `sudo mv /etc/pam.d/sudo.openhello.bak /etc/pam.d/sudo`.

## Registro por VM

| Distro | DE | Locker | Serviço PAM | Nível A/B | Resultado | Observações |
|---|---|---|---|---|---|---|
| openSUSE Tumbleweed | KDE Plasma 6.8 | kscreenlocker | kde-face | A | pendente | |
| | | | | | | |

Resultado: passou, falhou ou parcial (rosto desbloqueia mas sem mensagem, por exemplo). Em falha, anexe o trecho do log e o `pam-survey`.

## Suposições confirmadas (ASM-011)

- O locker executa o módulo open-hello de forma não interativa por um serviço PAM próprio, como usuário, em qualquer distro/desktop com PAM.
- O proxy PKCS#11 funciona sem root dentro do locker (T-025).
- Com o KDE desta máquina aprovado, marque AC-028 como provado; os demais ambientes seguem como "não verificado" até terem linha no registro.

## Live result on the KDE lock screen (2026-10-21)

Tested on the KDE neon VM (Plasma 6.8.0, kscreenlocker 6.8.0) with `openhello-cli pam enable kde --arg debug`, which adds `auth sufficient pam_openhello.so debug` as the first `auth` line of `/etc/pam.d/kde` and nothing else (no `kde-face`, no `kscreenlockerrc` change).

- `pam_openhello` logged `reason=success service=kde` at both lock attempts (19:01:51 and 19:06:01) and openhellod logged `verify uid=1000 accepted=true` plus `ticket delivery=delivered`: the face was recognised and the TPM signature verified inside the locker's own PAM service, as the unprivileged user.
- The lock screen then showed only an **Unlock** button, with no password field. This is KDE behaviour, read in `LockScreenUi.qml` (`onSucceeded`): the regular authenticator expects a prompt, and when it succeeds without ever prompting the greeter shows `NoPasswordUnlock`, which needs one click. Authenticators that do not expect a prompt (fingerprint, smartcard, face) call `Qt.quit()` and unlock directly.
- Decision (owner rule, no per-desktop adapters unless unavoidable): keep the one confirmation click. The direct unlock needs KDE's `Face` authenticator (`[Authenticators] Face=true`, the `kde-face` service and `[Greeter] Authenticator=Face`), which is KDE-only and has side effects; it stays an optional, explicit KDE step, never the default.
- Not measured: the time between locking and the Unlock button, and a second person at the camera. Earlier attempts failed for two reasons that were not the module: the module was missing from `/etc/pam.d/kde` after a failed `pam enable` (the CLI then rejected `--arg debug`), and before that the `<uid>.pub` file was missing.
