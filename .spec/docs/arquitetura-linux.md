# Arquitetura do open-hello (Linux)

Proposta de design baseada na engenharia reversa do Windows Hello (`windows-hello-arquitetura.md`). Mantém os invariantes de segurança que o Windows Hello preserva, troca os mecanismos específicos de plataforma (VBS, LSA, NGC) por equivalentes Linux, e aponta onde dá para reaproveitar infraestrutura madura já existente em vez de reconstruir do zero.

## Princípios de design (herdados da engenharia reversa)

1. **Biometria nunca é o segredo de autenticação.** Ela só autoriza o uso de uma chave assimétrica que já existe. Um template de rosto/digital nunca vira, ele mesmo, uma credencial.
2. **Uma chave assimétrica por usuário, selada em TPM 2.0.** A chave privada nunca sai do chip. Software fora do TPM nunca a vê em claro.
3. **"Protector" desacoplado da chave.** PIN e biometria são métodos intercambiáveis de autorizar o uso da mesma chave — não dois sistemas paralelos.
4. **Dois daemons com responsabilidades estritamente separadas**: um para captura/matching biométrico (nunca produz nem vê a chave), outro para posse/uso de chave (nunca vê dado biométrico bruto).
5. **Anti-brute-force ancorado em hardware**, não em contador de software que um processo comprometido poderia zerar.
6. **Plugins de três camadas com contrato mínimo** (Sensor → Engine → Storage Adapter), carregados dinamicamente, intercambiáveis por hardware/modalidade.

## Achado que muda a estratégia: o gap real não é captura, é a camada de credencial

O ecossistema Linux já resolve boa parte da camada 1 (hardware/captura) com qualidade de produção:

- **`libfprint` + `fprintd`** — já é, na prática, um WbioSrvc para impressão digital: daemon D-Bus (`net.reactivesys.Fprint`), enrollment, verificação, templates persistidos, dezenas de drivers de sensor suportados. Tem até um módulo PAM (`pam_fprintd`).
- **Howdy** (`github.com/boltgolt/howdy`) — reconhecimento facial via câmera IR em PAM, já lida com a mesma classe de hardware que o Windows Hello Face usa (câmeras IR "Windows Hello certified", que aparecem como `/dev/videoN` extra — exatamente como a engenharia reversa confirmou para o lado Windows).

**O que nenhum dos dois faz, e é exatamente o que falta no Windows-side da análise**: nenhum transforma o resultado do matching biométrico numa autorização de uso de uma chave criptográfica real. Ambos gatekeeiam PAM com um booleano — o template biométrico em si é o fator de decisão, sem chave assimétrica, sem TPM, sem nada reutilizável fora do login local (não dá pra usar o mesmo "Hello" pra desbloquear um cofre de senhas, assinar um commit, autenticar SSH, etc.).

**Conclusão de design**: o valor novo do open-hello não é reinventar sensor/engine de impressão digital ou rosto — é construir a camada que falta: um **equivalente ao NGC** (chave por usuário selada em TPM, liberável por Protectors intercambiáveis, exposta de forma padrão o suficiente para ser consumida por login, `sudo`, SSH, gerenciador de senhas, LUKS). Onde fizer sentido, open-hello deve **integrar com `fprintd`/Howdy como provedores de Sensor+Engine**, em vez de competir com eles.

## Visão geral dos componentes

```
┌──────────────────────────────────────────────────────────────────┐
│ CONSUMIDORES DE IDENTIDADE                                         │
│   pam_pkcs11 (login/sudo/lock) · ssh (PKCS#11 agent) · apps (D-Bus)│
├──────────────────────────────────────────────────────────────────┤
│ openhello-keyd   (equivalente ao NGC — root-only, sem rede)        │
│   chave por usuário selada no TPM · exposta como token PKCS#11     │
│   via tpm2-pkcs11 · Protectors (PIN/biometria) como authValue       │
├──────────────────────────────────────────────────────────────────┤
│ openhellod       (equivalente ao WinBio — captura/matching)        │
│   D-Bus system bus · sessão/foco/lock · plugins Sensor/Engine/Store │
│   integra fprintd (digital) e um engine próprio (rosto)            │
├──────────────────────────────────────────────────────────────────┤
│ HARDWARE                                                            │
│   leitor de digital (USB/UMDF-like) · câmera IR (V4L2) · TPM 2.0    │
└──────────────────────────────────────────────────────────────────┘
```

## `openhellod` — daemon de biometria

Papel equivalente ao `WbioSrvc`: orquestra sensor/engine/storage, nunca toca em chave criptográfica.

- **Transporte**: D-Bus system bus, serviço `io.openhello.Biometrics1`. Cada chamada carrega o `SO_PEERCRED`/sender do D-Bus como identidade — equivalente direto ao `RpcImpersonateClient` por chamada do WinBio, sem precisar reconstruir o aparato NDR/ALPC completo.
- **Operações**: `OpenSession`, `EnumUnits`, `CaptureSample`, `EnrollBegin/Capture/Commit/Discard`, `Identify`, `Verify`, `AcquireFocus/ReleaseFocus`, `LockUnit/UnlockUnit` — mesmo vocabulário do WinBio, mapeado 1:1 onde possível para facilitar auditoria cruzada com a documentação do Windows.
- **Arbitragem de foco**: necessária desde o v1 — o greeter (GDM/SDDM) e uma sessão de usuário ativa podem disputar a mesma câmera/sensor ao mesmo tempo. Replica `AcquireFocus`/`ReleaseFocus` do Windows.
- **Plugins**: contrato C simples — um `.so` por adapter, um símbolo de entrada (`openhello_sensor_interface()`, `openhello_engine_interface()`, `openhello_storage_interface()`) retornando uma struct de ponteiros de função, carregado via `dlopen`/`dlsym`. Réplica direta do `WbioQuery<Camada>Interface` do Windows — nada de D-Bus/COM entre o daemon e os plugins, é tudo in-process.

### Sensor + Engine Adapter — impressão digital

Não reimplementar. `openhellod` fala com `fprintd` via D-Bus como se fosse seu próprio Sensor+Engine Adapter combinado (libfprint já faz captura e matching internamente). O "adapter" aqui é um shim fino que traduz `EnrollBegin/Capture/Commit`/`Verify` do open-hello para as chamadas equivalentes da API do `fprintd`.

### Sensor + Engine Adapter — rosto

Este é o trabalho novo real.

**Hardware confirmado nesta máquina** (verificado via `/sys/class/video4linux`, `lsusb -v`): um único dispositivo USB (Sunplus `2b7e:c757`, "FHD Webcam") expõe duas coleções de função UVC distintas — `/dev/video0`/`video1` (RGB, interface 1.0) e `/dev/video2`/`video3` (nomeada "IR Camera" pelo próprio firmware, interface 1.2, formato `Greyscale 8-bit 640x360`). Ambas já enumeram via `uvcvideo` padrão do kernel, sem driver adicional — mais simples que os módulos Intel IPU6/MIPI de notebooks mais novos (sem suporte maduro no Linux mainline ainda). Isso valida a suposição da proposta: a câmera IR é só mais um nó V4L2, distinguível pelo nome do dispositivo e pela topologia USB (interface diferente dentro do mesmo `idVendor:idProduct`), sem precisar de heurística complexa.

**Achado adicional, não previsto na primeira versão desta proposta**: o dispositivo expõe 5 *Extension Units* UVC (controles proprietários do fabricante), incluindo um GUID repetido (`63610682-5070-49ab-b8cc-b3855e8d221d`, 26 e 25 controles) — assinatura típica de câmeras Windows Hello que mantêm o **emissor IR (projetor de pontos/flood) desligado por padrão**, ligado só por um controle XU específico do fabricante. Isso é exatamente o problema que o projeto `linux-enable-ir-emitter` resolve (banco de dados comunitário de GUID+índice+payload por modelo de câmera). **Sem isso resolvido, o Sensor Adapter de rosto pode capturar frames sem iluminação IR ativa** — pior para reconhecimento e crítico para liveness/anti-spoof (a textura IR só é confiável com o emissor ligado).

- **Sensor**: V4L2 sobre o nó IR dedicado (confirmado acima), mais uma etapa de ativação do emissor IR via controle XU — usar o banco de dados do `linux-enable-ir-emitter` como ponto de partida para descobrir o payload certo para este GUID/vendor, antes de assumir frames "limpos" do sensor.
- **Engine**: extração de embedding facial via ONNX Runtime (candidato concreto abaixo) + matching calibrado por FAR + uma etapa de liveness/anti-spoof usando o sinal IR (textura/profundidade, só confiável com o emissor ligado). **Documentar explicitamente desde o v1** que esse anti-spoof é mais fraco que o "Enhanced Sign-in Security" do Windows (que roda em trustlet VBS) — não há hardware equivalente de isolamento disponível por padrão em laptops Linux.

### Candidato de modelo para o v1a (deep-research, 101 subagentes, claims verificados por voto adversarial)

**Recomendado: AuraFace (checkpoint `glintr100`, arquitetura IResNet100+ArcFace, Apache-2.0, [huggingface.co/fal/AuraFace-v1](https://huggingface.co/fal/AuraFace-v1))**, com **YuNet** (MIT, OpenCV Zoo) como detector. Três pilares de evidência, não um só:

1. **Precedente de produção quase idêntico**: o projeto [`nirlock`](https://github.com/lordyoyi/nirlock) (MIT) já roda exatamente essa combinação (YuNet + AuraFace/glintr100, com SFace Apache-2.0 como alternativa) sobre hardware **idêntico ao nosso** — nó V4L2 `GREY` 640x360, CPU-only via `onnxruntime`. Projeto pequeno (1 estrela, validado numa câmera/num rosto), não é benchmark — mas é a única confirmação de que o pipeline inteiro (grayscale IR → ONNX Runtime → embedding) roda de ponta a ponta em hardware comparável.
2. **Teoria de generalização zero-shot confirma a escolha do backbone GRANDE, não pequeno**: Tarasiou et al. (CVPR-W 2024, [arXiv:2312.00627](https://arxiv.org/pdf/2312.00627)) mede backbones IResNet treinados só em RGB, sem nenhum fine-tuning em NIR: **IR50/IR100 atingem ~99% zero-shot em NIR-VIS** (CASIA NIR-VIS 2.0, Lamp-HQ, Oulu-CASIA), enquanto **arquiteturas pequenas como LightCNN-29/MobileFaceNet caem para 85–96%** no mesmo domain shift. AuraFace/`glintr100` é da classe IR100 (~65M parâmetros) — o tamanho que a literatura associa a generalização boa para IR, não o SFace leve que era o candidato pragmático original.
3. **Correção de premissa**: o candidato anterior, **LightCNN-29 v2, na verdade nunca foi treinado em CASIA NIR-VIS 2.0** — o release oficial (MIT) é treinado só em CASIA-WebFace + MS-Celeb-1M (RGB puro); os números NIR-VIS citados na literatura vêm de fine-tunes de terceiros, não do checkpoint público. Essa pista inicial estava errada.

**O que é tecnicamente melhor no papel mas não é usável hoje**: `xEdgeFace-Base` (Idiap, IJCB 2025) — 99.99% rank-1 em CASIA NIR-VIS 2.0, só 18M parâmetros/1.39 GFLOPs (muito mais leve que o AuraFace) — mas **pesos e código nunca foram publicados** (18 meses pós-preprint, só a promessa "we will release"). A predecessora disponível, `EdgeFace`, está sob **CC BY-NC-SA 4.0** (não-comercial) — incompatível com a licença MIT do projeto.

**Riscos honestos documentados pela pesquisa**: (a) não existe benchmark NIR-VIS publicado para o checkpoint exato `glintr100` — a evidência de generalização vem de arquiteturas comparáveis, não do mesmo modelo testado em NIR; (b) validação de campo (`nirlock`) cobre uma câmera e um rosto, não é prova estatística; (c) ~65M parâmetros é "classe pesada" segundo a comparação do paper xEdgeFace — medir latência real em CPU antes de comprometer o v1a a esse modelo; (d) fine-tuning ingênuo em poucos dados NIR **piora** a acurácia em vez de melhorar (o paper mostra fine-tune cru derrubando IR50 de 99,03% para 97,72%) — só vale investir em fine-tuning com uma receita regularizada específica, não um fine-tuning simples.

**Plano de execução (orçamento de esforço da Q15)**: ~2 semanas testando AuraFace/`glintr100` zero-shot (sem fine-tuning) contra os datasets NIR já localizados (uso local/offline) e contra fixtures gravadas da própria câmera, medindo latência em CPU; se a acurácia empírica ficar inaceitável ou a latência inviabilizar o v1a, cai para SFace (mais leve, mesma licença Apache-2.0, já confirmado em uso real no `nirlock` como alternativa) antes de considerar o fallback estilo Howdy.
- Avaliar: reaproveitar o pipeline de captura/liveness do Howdy como ponto de partida para o Engine Adapter, em vez de escrever do zero — e, como o Howdy já tem lógica de ativação de emissor IR para câmeras Windows Hello, também como referência para resolver o XU deste modelo específico.

**Critério de matching — adotar o modelo mental do Windows Hello, não um corte arbitrário.** A RE (decompilação de `FaceRecognitionEngineAdapter.dll`) confirmou que o Windows Hello Face não compara embeddings por "distância de cosseno > X" — o conceito nativo do sistema é **taxa de falso aceite (FAR) calibrada**, com alvo de decisão **1×10⁻⁵ (1 em 100.000)** confirmado como constante real no binário (não só o número de marketing). O Engine Adapter do open-hello deve replicar essa filosofia: o parâmetro público/configurável é um **FAR alvo** (ex.: `1e-5` por padrão), e uma camada de calibração interna converte a saída bruta do modelo escolhido (distância euclidiana, cosseno, o que for) nessa unidade antes de decidir aceitar/rejeitar — por exemplo, calibrando a distribuição de scores de impostor num conjunto de validação e derivando o corte que corresponde ao FAR alvo, em vez de chutar um threshold de distância sem significado estatístico. Isso também torna a segurança do open-hello diretamente comparável à do Windows Hello na documentação ("mesmo alvo de 1 em 100.000").

**Próxima validação recomendada**: instalar `v4l-utils` (pacote `zypper install v4l-utils`, ainda não presente no sistema) para testar streaming real do nó IR com `v4l2-ctl --device=/dev/video2 --stream-mmap` e confirmar visualmente se o emissor já liga sozinho ou precisa do XU.

### Storage Adapter

- Formato de arquivo versionado por usuário (`/var/lib/openhello/templates/<uid>.db`): header com magic + versão + schema, seguido de registros (um por template enrolled).
- Cifra: **AEAD real desde o v1** — AES-256-GCM ou ChaCha20-Poly1305 (confidencialidade + integridade no mesmo primitivo). Isso é uma melhoria deliberada sobre o Windows, que usa AES-256-CBC sem tag própria (a RE confirmou isso por decompilação).
- Chave de cifra do banco: **selada no TPM** (`tpm2_create` sob uma primary key do owner hierarchy), não protegida por um análogo de DPAPI — o Linux não tem DPAPI, e usar o TPM aqui é estritamente mais forte que a solução do Windows para esta camada específica.

## `openhello-keyd` — daemon de chave/credencial (equivalente ao NGC)

Processo separado de `openhellod`, privilégio mínimo (UID dedicado, sem rede, `NoNewPrivileges`, seccomp estrito, `ProtectKernelModules`/`ProtectKernelTunables` via systemd). É o único processo que fala com o TPM para operações de chave.

### Chave por usuário

- Criada com `tpm2-tools` (`tpm2_createprimary` + `tpm2_create`), atributos equivalentes a `fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign` — nunca exportável.
- Exposta ao resto do sistema como um **token PKCS#11** via `tpm2-pkcs11`. Esse é o paralelo direto do truque "smart card GIDS virtual" que a engenharia reversa encontrou no Windows: em vez de inventar um protocolo de autenticação novo, o open-hello se encaixa na pilha PKCS#11/smart-card que já existe no Linux (`pam_pkcs11`, agente PKCS#11 do OpenSSH, Firefox/Chrome via NSS, `cryptsetup`/LUKS com token).

### Protector (PIN/biometria)

Réplica fiel do mecanismo real encontrado na decompilação do `NgcCtnrSvc.dll`: cada Protector é **um segredo de 20 bytes gerado em software** (via CSPRNG, não exige operação de TPM para ser criado) mais um HMAC-SHA256 de ligação. Esse segredo é o `authValue` que satisfaz a política de autorização da chave TPM. Diferente do Windows (onde não foi encontrado nenhum contador de hardware amarrado a essa geração), aqui o **TPM2 Dictionary Attack Lockout** nativo é usado para throttling — presença de tentativa de uso incorreto do `authValue` já é contabilizada pelo próprio chip, resistente a rollback por reinício do SO. Isso é uma melhoria sobre o que foi observado no lado Windows nesta análise.

- PIN: o usuário digita, o Protector-PIN é derivado/comparado localmente antes de apresentar o `authValue` ao TPM.
- Biometria: `openhellod` emite um **ticket de sessão de curta duração** (assinado/HMAC com uma chave efêmera compartilhada só entre os dois daemons) após `Verify`/`Identify` bem-sucedido. `openhello-keyd` valida o ticket (freshness + assinatura) e, só então, libera o Protector-biometria correspondente para satisfazer a política da chave.

### Integração com login: reaproveitar `pam_pkcs11`, não escrever PAM do zero

Como a chave já é um token PKCS#11, a forma recomendada de ligar isso ao logon é configurar o **`pam_pkcs11` existente** (maduro, já testado contra smart cards físicos) para confiar nesse token virtual, em vez de escrever um módulo PAM novo com lógica de desafio-resposta própria. O único componente novo necessário é um **shim de login da sessão PKCS#11**: `tpm2-pkcs11` pede um PIN em `C_Login`; o shim intercepta esse login e só repassa o PIN real (= o Protector ativo) depois de `openhellod` confirmar um match biométrico fresco — unificando PIN e biometria como a mesma entrada de baixo nível que o PKCS#11 já espera.

Isso dá de graça, sem trabalho adicional: `sudo` com biometria/PIN (via `pam_pkcs11` no stack do `sudo`), desbloqueio de tela, e potencialmente SSH (agente PKCS#11) e LUKS (token PKCS#11 do `cryptsetup`) usando a mesma chave.

## API de consentimento pontual (equivalente ao `UserConsentVerifier`)

Interface D-Bus fina, `io.openhello.ConsentVerifier1`, método `RequestVerification(mensagem) -> resultado`, para apps que só precisam confirmar "é o dono do dispositivo" sem fazer login completo (ex. destravar um gerenciador de senhas). Chama internamente o mesmo fluxo de `Verify` de `openhellod`; o app nunca recebe template nem chave, só o resultado.

## Fluxo de enrollment (passo a passo)

1. Usuário inicia enrollment (CLI/GUI do open-hello).
2. `openhello-keyd` cria a chave TPM do usuário (se ainda não existe) e o token PKCS#11 correspondente.
3. `openhellod` conduz `EnrollBegin` → `EnrollCapture` (repete até qualidade suficiente, via Sensor+Engine Adapter) → `EnrollCommit`, gravando o template cifrado via Storage Adapter.
4. `openhello-keyd` gera o Protector-biometria (20 bytes + HMAC) e o associa à política de autorização da chave.
5. Fim: usuário tem uma chave TPM utilizável, destravável por PIN e/ou pelo fator biométrico recém-enrolado.

## Fluxo de logon (passo a passo)

1. `pam_pkcs11` pede autenticação; o shim PKCS#11 bloqueia em `C_Login` aguardando um fator.
2. Usuário olha pra câmera/encosta o dedo → `openhellod` faz `Verify` (Sensor→Engine locais, nunca saem da máquina) → sucesso emite ticket de sessão.
3. Shim PKCS#11 recebe o ticket, repassa ao `openhello-keyd`, que valida e libera o Protector-biometria como `authValue`.
4. `tpm2-pkcs11` completa `C_Login` com o `authValue` liberado → operações de assinatura ficam disponíveis na sessão PKCS#11 pelo tempo necessário.
5. `pam_pkcs11` completa o desafio-resposta padrão (chalenge assinado pela chave) → PAM retorna sucesso → sessão desbloqueada.

## Isolamento e modelo de ameaça — onde ficamos mais fracos/mais fortes que o Windows

| Camada | Windows Hello | open-hello (proposta) | Avaliação |
|---|---|---|---|
| Chave assimétrica do usuário | Selada em TPM, `Microsoft Platform Crypto Provider` | Selada em TPM, `tpm2-pkcs11` | Equivalente |
| Isolamento do processo que opera a chave | Trustlet VBS (hypervisor Hyper-V + Secure Kernel) | Daemon root-only com seccomp/namespaces, sem TEE | **Mais fraco** — documentar isso abertamente; upgrade futuro possível via SGX/TDX/TrustZone se o hardware tiver |
| Cifra do banco de templates | AES-256-CBC + DPAPI (sem tag própria) | AES-256-GCM/ChaCha20-Poly1305 selada no TPM | **Mais forte** |
| Anti-brute-force do Protector | Não identificado contador de hardware na geração do segredo (rodada de decompilação não achou chamada TPM ali) | TPM2 Dictionary Attack Lockout nativo | **Mais forte** |
| Reaproveitamento de pilha de logon existente | Smart card virtual GIDS → PKINIT/Kerberos | Token PKCS#11 virtual → `pam_pkcs11` | Equivalente em espírito |
| Anti-spoofing facial | Engine do fabricante da câmera + enforcement "Enhanced Sign-in Security" no framework | Heurística IR própria/Howdy, sem enforcement de hardware | **Mais fraco** — ser explícito sobre essa limitação para o usuário final |

## O que reaproveitar vs. o que é novo

| Componente | Reaproveitar | Construir |
|---|---|---|
| Captura/matching de digital (futuro, sem hardware hoje) | `libfprint`/`fprintd` inteiros | shim de tradução de API |
| Captura de rosto | V4L2 + ativação de emissor IR (banco de dados do `linux-enable-ir-emitter` para o GUID já identificado) | — |
| Matching/liveness de rosto | ponto de partida: pipeline do Howdy | engine com embedding + anti-spoof refinado |
| Chave TPM + token | `tpm2-tools`, `tpm2-pkcs11` | provisionamento específico do open-hello (Protectors) |
| Integração com login | `pam_pkcs11` | shim de PIN/biometria no `C_Login` |
| Orquestração biometria | — | `openhellod` (D-Bus, plugins, foco/sessão) |
| Credencial/Protector | TPM2 policy session | `openhello-keyd` inteiro |

## Roadmap de fases

**Sem leitor de impressão digital neste laptop** — o v1 é obrigatoriamente rosto. O plano de fases original (começar por digital via `fprintd`, mais simples, como prova de conceito do backend de credencial) não se aplica a este hardware. A arquitetura dos dois daemons continua igual independente da modalidade — o que muda é que todo o peso do v1 cai no caminho mais difícil (Sensor+Engine de rosto), sem o atalho de validar o resto do sistema primeiro com um sensor mais simples. Por isso vale dividir o v1 em duas sub-fases, para não acoplar "câmera funcionando" a "TPM/PAM funcionando" no mesmo lote de trabalho:

- **v1a — prova de reconhecimento (sem TPM/PAM ainda)**: `openhellod` sozinho, rodando por CLI. Sensor Adapter (V4L2 no nó IR + ativação do emissor via XU, usando o GUID já identificado) + Engine Adapter (embedding + matching + liveness básico) + Storage Adapter (templates cifrados). Critério de pronto: enrollment e verify funcionando de forma confiável na sua própria cara, sem nenhuma integração de login ainda. Esse é o maior risco técnico do projeto — validar isso primeiro, isolado, evita descobrir problemas de reconhecimento só depois de já ter construído a camada de credencial em cima.
- **v1b — integração de credencial**: `openhello-keyd` com chave TPM/token PKCS#11 + `pam_pkcs11` configurado + shim de login que troca o PIN pelo resultado do `Verify` do v1a. Fecha o fluxo ponta a ponta: olhar pra câmera → desbloquear.
- **v2**: anti-spoof mais robusto (hoje documentado como ponto fraco frente ao "Enhanced Sign-in Security" do Windows), UX de greeter (GDM/SDDM) com indicação visual de biometria disponível.
- **v3 (opcional)**: Sensor+Engine Adapter de impressão digital via `fprintd`, caso o usuário ganhe/compre hardware com leitor — a arquitetura já foi desenhada para isso, é só mais um plugin. API de consentimento pontual para apps (D-Bus), integração LUKS/SSH via o mesmo token PKCS#11.
- **Futuro, condicionado a hardware**: avaliar TEE (SGX/TDX/TrustZone/OP-TEE) para aproximar o nível de isolamento do trustlet VBS, caso o projeto queira mirar paridade total de segurança com "Enhanced Sign-in Security".

## Decisões em aberto (precisam de validação do usuário antes de codar)

1. **Algoritmo da chave TPM**: ECDSA P-256 (mais rápido, chaves menores) vs. RSA-2048 (compatibilidade mais ampla com `pam_pkcs11`/ferramentas antigas). Recomendação: ECDSA se a validação com `pam_pkcs11` comprovar suporte no ambiente alvo; RSA como fallback.
2. **Mecanismo exato do ticket biométrico entre `openhellod` e `openhello-keyd`**: HMAC com chave efêmera trocada via socket Unix com `SO_PEERCRED`, ou algo mais formal (ex. um pequeno protocolo desafio-resposta). Para v1, HMAC simples é suficiente dado que ambos os processos rodam na mesma máquina sob root.
3. **Escopo do anti-spoof facial no v1**: aceitar heurística IR simples (mais rápido de entregar, risco de spoofing maior) ou investir desde já num classificador de liveness mais robusto (mais trabalho, mais seguro). Recomendo começar simples e documentar o risco, dado que o objetivo inicial é provar a arquitetura de credencial, não competir em robustez de anti-spoof com o Windows.
4. **Hardware alvo real — confirmado**: não há leitor de impressão digital neste laptop — **o v1 é rosto, sem alternativa mais simples para validar primeiro**. A câmera IR aparece como par dedicado `/dev/video2`/`video3` (V4L2 puro, via `uvcvideo`), sem precisar de driver especial. Falta confirmar o payload XU correto para ligar o emissor IR deste modelo específico (GUID `63610682-5070-49ab-b8cc-b3855e8d221d`) — sem isso, o Engine Adapter de rosto não tem sinal IR confiável para liveness. Essa é a validação técnica mais urgente antes de começar a codar o v1a.
