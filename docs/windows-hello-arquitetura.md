# Engenharia reversa do Windows Hello

Documento de referência para o projeto open-hello (reimplementação em Linux da autenticação biométrica local do Windows). Compilado a partir de engenharia reversa estática (leitura de exports, strings e metadados PE) sobre os binários da instalação Windows do próprio usuário, montada em `/mnt/windows`. Somente leitura — nenhum arquivo da partição Windows foi alterado.

## Método e limitações

A análise teve duas rodadas. A primeira usou o MCP REA só com `objdump -p`, `strings` e inspeção de bytes brutos (nenhum decompilador configurado) — achados vindos de exports, strings embutidas (incluindo caminhos de arquivo-fonte da Microsoft preservados nos binários, ex.: `onecore\ds\security\biometrics\...`) e tabelas de import. Onde essa rodada descrevia layout de campo binário exato ou sequência exata de chamadas CNG/TPM, isso era inferência razoável, não fato verificado — e, num caso (algoritmo de cifra do banco de templates), **a inferência estava errada** (ver seção de criptografia).

A segunda rodada configurou o Ghidra 12.1.4 como provedor de decompilação (`GHIDRA_INSTALL_DIR` + JDK 21) e decompilou linha a linha os quatro módulos que tinham ficado pendentes: `filelayout.cpp`/`crypto.cpp` (nos storage adapters) e `authvalue.cpp`/`pipeline.cpp` (em `wbiosrvc.dll`). Nenhum desses binários carrega PDB — os nomes de classe/método C++ foram perdidos; a reconstrução usou `procedure_callers`/`procedure_callees` a partir dos imports nomeados (`BCryptEncrypt`, `NCryptOpenStorageProvider`, `NgcAddBioProtector` etc.) e os caminhos de source-file embutidos para confirmar em qual arquivo cada função decompilada vive. Achados desta rodada estão marcados como "confirmado por decompilação" abaixo; o pipeline sensor→engine→storage e a lógica interna de `cryptngc.dll` (onde o AuthValue é de fato gerado) continuam pendentes — ver "Próximos passos".

Em ambos os casos: análise 100% de leitura sobre a partição Windows do usuário, montada em `/mnt/windows`. Nenhum arquivo original foi alterado.

## Visão geral da arquitetura

O Windows Hello não é um sistema monolítico — são três subsistemas empilhados, cada um com uma responsabilidade estrita:

```
┌─────────────────────────────────────────────────────────────┐
│ 3. LOGON / CREDENCIAIS                                       │
│    Credential Providers (COM) · NGC · chave TPM · LSA         │
├─────────────────────────────────────────────────────────────┤
│ 2. WinBio (Windows Biometric Framework)                       │
│    API cliente (winbio.dll) · serviço (wbiosrvc.dll) · RPC    │
│    Plugins: Sensor Adapter → Engine Adapter → Storage Adapter │
├─────────────────────────────────────────────────────────────┤
│ 1. HARDWARE                                                    │
│    Câmera IR (V4L2/MediaFrameSourceGroup) · leitor de digital  │
│    · TPM 2.0                                                   │
└─────────────────────────────────────────────────────────────┘
```

A regra de design central, confirmada em vários pontos independentes da análise: **a biometria nunca é o segredo de autenticação**. Ela é só o "destravador" local de uma chave assimétrica que já existe, protegida por TPM. Um template de rosto ou digital nunca trafega para fora da máquina nem vira, ele mesmo, uma credencial.

## Camada 1 — API cliente (`winbio.dll`)

`winbio.dll` expõe ~89 funções exportadas, todas prefixadas `WinBio*`. `winbioext.dll` é só um forwarder COM sem lógica própria. Por categoria:

**Sessão/framework**: `WinBioOpenSession`, `WinBioAsyncOpenSession`, `WinBioAsyncOpenFramework`, `WinBioCloseSession`, `WinBioCloseFramework`, `WinBioWait`, `WinBioCancel`, `WinBioFree`.

**Enumeração**: `WinBioEnumBiometricUnits`, `WinBioEnumServiceProviders`, `WinBioEnumDatabases`, `WinBioLocateSensor`, `WinBioGetConnectedSensors`, `WinBioAsyncMonitorFrameworkChanges`.

**Captura**: `WinBioCaptureSample`, `WinBioCaptureSampleWithCallback`.

**Enrollment**: `WinBioEnrollBegin` → `WinBioEnrollCapture` (repetido até qualidade suficiente) → `WinBioEnrollCommit`; mais `WinBioEnrollDiscard`, `WinBioEnrollRevoke`, `WinBioEnrollSelect`, `WinBioEnrollAuthorize`, `WinBioEnumEnrollments`, `WinBioDeleteTemplate`, `WinBioImproveBegin`/`End` (retreino incremental de template já existente).

**Matching**: `WinBioVerify` (1:1, identidade alegada) e `WinBioIdentify` (1:N, busca no banco inteiro), cada uma com variante `WithCallback` e `AndReleaseTicket`.

**Credenciais/logon**: `WinBioSetCredential`, `WinBioGetCredentialState`, `WinBioGetCredentialWithTicket`, `WinBioRemoveCredential`(`All`/`AllDomain`), `WinBioLogonIdentifiedUser`, `WinBioNotifyPasswordChange`.

**NGC**: `WinBioNgcOpenAuthorizationSession`, `WinBioNgcCloseAuthorizationSession`, `WinBioNgcAuthorizeEnrollment`, `WinBioNgcGetAuthorizationWithTicket` — a ponte explícita entre "match biométrico" e "autorização de uso de chave NGC".

**Enhanced Sign-in Security (ESS)**: `WinBioIsESSCapable`, `WinBioGetEssState`, `WinBioIsDeviceEnhancedSignInSecurityCapable/Enabled`, `WinBioAreEnhancedSignInSecurityRequirementsMet` — consulta se o hardware suporta o caminho com isolamento VBS (seção 4).

**Proteção de dados/políticas**: `WinBioProtectData`/`UnprotectData`/`ProtectDataWithPolicy`, `WinBioGetSetting`/`SetSetting`, `WinBioGetProperty`/`SetProperty`, `WinBioGetLogonSetting`, `WinBioGetDomainLogonSetting`.

**Eventos/foco**: `WinBioRegisterEventMonitor`, `WinBioRegisterServiceMonitor`, `WinBioMonitorPresence`, `WinBioAcquireFocus`/`ReleaseFocus` (exclusividade de captura entre processos concorrentes, ex. tela de bloqueio vs. app).

**Administração**: `WinBioControlUnit`/`Privileged` (IOCTL genérico passthrough), `WinBioLockUnit`/`UnlockUnit`, `WinBioGetLastBioUseTime`, `WinBioGetGestureMetadata`, `WinBioSendTelemetry`.

### Estruturas de dados centrais

Não extraídas por decompilação, mas confirmadas como corretas contra os binários reais (ex.: a string `reinterpret_cast<const SID*>(enrollmentSid.Value.AccountSid.Data)` em `wbiosrvc.dll` confirma o layout de `WINBIO_IDENTITY` documentado publicamente):

- **`WINBIO_IDENTITY`** — union discriminada por `Type`: nulo, wildcard, SID de conta Windows, ou GUID de template.
- **`WINBIO_UNIT_SCHEMA`** — `UnitId`, `PoolType` (sensor/intermediário/virtual), `BiometricFactor` (bitmask: digital/rosto/íris/voz), `SensorSubType`, `Capabilities`, `DeviceInstanceId`.
- **`WINBIO_BIR`** (Biometric Information Record) — envelope padrão CBEFF/BioAPI: header padronizado + payload opaco específico do provedor (BSP).

### Transporte cliente → serviço

`winbio.dll` é um stub cliente RPC (`RpcBindingFromStringBindingW`, `RpcAsyncInitializeHandle`, `RpcBindingSetAuthInfoExW`). A string literal `ncalrpc` confirma **RPC local sobre ALPC**, não rede — não há import de Winsock/HTTP em nenhum dos binários desta camada.

## Camada 2 — Serviço (`WbioSrvc`) e plugins

`WbioSrvc` não é um `.exe`: é uma service-DLL (`wbiosrvc.dll`) hospedada dentro de `svchost.exe` (confirmado por `ServiceMain`, `SvchostPushServiceGlobals`, `RegisterServiceCtrlHandlerExW`).

### Dispatch RPC (servidor)

Cada operação pública vira uma classe C++ interna `CWinBioSrv<Verbo>::Execute`, chamada via NDR (`NdrServerCall2`, `NdrAsyncServerCall`). Cada chamada é processada com **impersonation do cliente** (`RpcImpersonateClient`/`RpcRevertToSelf`) para checagem de ACL por chamada, revertendo ao contexto do serviço depois. Lista confirmada de operações do servidor: `OpenBiometricSession`, `OpenFrameworkSession`, `EnumBiometricUnits`, `EnumServiceProviders`, `LocateSensor`, `MonitorFrameworkChanges`, `CaptureSample`, `GetPresenceData`, `GetEvent`, `EnrollBegin/Capture/Commit(Execute/AuthRelease)/Discard/Revoke/Select/Authorize`, `EnumEnrollments`, `DeleteTemplate`, `ImproveBegin/End`, `Identify`/`IdentifyAndReleaseTicket`, `Verify`/`VerifyAndReleaseTicket`, `LockUnit`/`UnlockUnit`, `ControlUnit`/`Privileged`, `GetProperty`/`SetProperty`, `ProtectData`/`UnprotectData`, **`LogonIdentifiedUser`** (o serviço, já SYSTEM, autoriza o logon — o cliente nunca decide isso sozinho), `AcquireFocus`/`ReleaseFocus`, rotinas de energia (`SensorPowerOnWait`, `SuspendComplete`, `ResumeBegin/Complete`, integradas ao `UMPDC.dll` — User-Mode Power Dependency Coordinator).

### Contrato de plugin: três interfaces, uma função de entrada cada

Confirmado por export literal — não é COM/`IUnknown`, é uma vtable C simples:

| DLL | Export | Camada |
|---|---|---|
| `winbiosensoradapter.dll` | `WbioQuerySensorInterface` | Sensor Adapter |
| `winbiostorageadapter.dll` | `WbioQueryStorageInterface` | Storage Adapter |
| `winbiovsmstorageadapter.dll` | `WbioQueryStorageInterface` | Storage Adapter (variante VSM) |
| `FaceBootstrapAdapter.dll` | as três (`Sensor`+`Engine`+`Storage`) | dispositivo virtual composto |

O host (`wbiosrvc.dll`) chama a função de entrada uma vez no carregamento do plugin, recebe a tabela de ponteiros de função, e passa a invocar diretamente. `PlugInLoadCheckSigningLevel` confirma que o serviço valida o nível de assinatura de código do plugin antes de carregar (hardening específico do Windows/Code Integrity).

Fluxo de dados (confirmado pela cadeia de módulos internos, `pipeline.cpp` orquestrando): **Sensor Adapter** captura amostra bruta (overlapped I/O via `DeviceIoControl`/`CancelIoEx` sobre um handle de dispositivo) → **Engine Adapter** extrai features, produz template e faz matching (`Identify`/`Verify`) → **Storage Adapter** grava/lê o blob cifrado em disco.

### Pipeline de captura confirmado por decompilação (`CWinBioSrvCaptureSample::Execute`)

As ~30 operações `CWinBioSrv*` listadas acima são nomes de RTTI (strings de diagnóstico embutidas), não símbolos de função resolvíveis por busca direta. A função real foi localizada seguindo `xrefs` a partir da string RTTI `"CWinBioSrvCaptureSample::Execute"` até seu único referenciador (confirmado pelo próprio corpo gravar essa string em tracing). Sequência real:

1. **Validação de handle/sessão**: duas checagens sobre o contexto da unidade e o contexto do chamador; falha retorna códigos de erro próprios do WinBio (facility `0x80098xxx`, ex. `0x8009802a`/`0x80098007`).
2. **Checagem de lock**: se a unidade biométrica está travada por outro processo, aborta com `0x80098004` ("ocupado") — este é o ponto de arbitragem de foco (`AcquireFocus`/`LockUnit`).
3. **Resolução do adapter bundle**: a unidade carrega, em um offset fixo da sua estrutura, um ponteiro para um bloco com (ao menos) dois sub-ponteiros de interface, cada um apontando para uma vtable de adapter diferente.
4. **Cálculo de parâmetros de captura** antes de qualquer acesso a hardware — resolve flags/qualidade esperada; erro aqui aborta sem tocar o sensor.
5. **Dois caminhos de disparo**, selecionados por um bit de flags no objeto `Execute`:
   - **Caminho direto**: chama a vtable interpretada como **Sensor Adapter** — modo "captura crua", um único salto.
   - **Caminho normal**: opcionalmente dispara uma notificação de início ("CaptureStarted"), depois chama a vtable interpretada como **Engine Adapter** — captura em dois estágios.
6. **Checagem de "já em captura"**: evita reentrância, abortando sem acionar hardware de novo se uma captura já está em andamento.
7. **Cleanup e devolução**: libera o contexto de captura e grava os resultados (handle de amostra, tamanho, flags) diretamente nos campos de saída do objeto RPC para marshaling de volta ao cliente.

**Interpretação**: na operação `CaptureSample`, o Sensor Adapter e o Engine Adapter aparecem como dois ponteiros de vtable irmãos dentro do mesmo "unit bundle" (não uma cadeia sequencial de 3 camadas nesta função específica) — faz sentido, já que captura não grava nada ainda, então o Storage Adapter não entra aqui.

### `EnrollCommit` — onde o Storage Adapter entra (parcialmente resolvido)

A string RTTI `"CWinBioSrvEnrollCommit::Execute"` tem exatamente um xref, mas ele cai dentro de uma função de ~786 linhas de pseudocódigo (bem maior que `CaptureSample`) — um dispatcher cobrindo múltiplos estados do commit, não uma função enxuta por operação. Confirmado nela: mesmo padrão de validação de sessão/lock e códigos de erro já visto em `CaptureSample`; três chamadas repetidas ao mesmo padrão de vtable, cada uma seguida de uma checagem de **consistência de tipo/fator biométrico** (compara o fator retornado pelo adapter contra o fator esperado da unidade), repetida em pontos diferentes do fluxo — não uma cadeia sequencial sensor→engine→storage isolável com confiança neste nível de leitura. Logo depois dessas checagens há uma sequência de três chamadas a funções não decompiladas, candidatas fortes a serem as transições de estado "begin/validate/commit" do registro no Storage Adapter, mas sem confirmação de qual delas de fato grava o template em disco.

**Pendente**: isolar com confiança o ponto exato em que o Storage Adapter grava o blob cifrado (distinto do Engine Adapter, que só valida o fator) exigiria decompilar essas três funções e mapear qual vtable (Sensor vs. Engine, no padrão já visto em `CaptureSample`) cada uma usa. `Identify`/`Verify` não foram localizadas nesta rodada.

### Driver interface (WBDI)

O sensor adapter genérico descobre hardware via ConfigMgr/SetupAPI (`CM_Get_Device_Interface_ListW`, `CM_Get_Device_Interface_PropertyW`, `CM_Locate_DevNodeW`) — o GUID da classe de interface "Windows Biometric Driver Interface" é documentado publicamente pela Microsoft, não extraído em texto claro do binário (GUIDs não aparecem como string ASCII). Após resolver o device path, a comunicação é `CreateFile` + `DeviceIoControl` overlapped. Não há `.sys` dedicado a biometria no sistema — leitores de digital tipicamente usam UMDF (driver em modo usuário, refletido pelo `WUDFRd.sys` genérico do sistema), não driver de kernel próprio por fabricante.

### Isolamento VSM/VBS (Enhanced Sign-in Security)

O serviço contém dois caminhos de execução lado a lado, confirmados pelas strings `hasVBSWindowsHello`/`hasNonVBSWindowsHello`, `requiresVBSEncryptionKeys`, `requiresIsolatedProcess`:

- Caminho legado: matching e chaves no processo normal, protegidos por CNG/DPAPI.
- Caminho ESS: matching biométrico e posse de chave acontecem dentro de um **trustlet de Isolated User Mode** (`Microsoft.Windows.Security.Biometrics.Trustlet`, controlado via `VbsApi.dll`, hypervisor Hyper-V + Secure Kernel), inacessível mesmo a um kernel Windows comprometido.

Módulos internos do trustlet (confirmados por PDB path): `bioisoapi.cpp`, `hmac.cpp` (integridade), `tpmpolicysession.cpp`/`tpmsupport.cpp` (sessões de política TPM2), e **`velocitycallback.cpp`** — throttling anti-força-bruta, plausivelmente contabilizado por um contador monotônico dentro do próprio TPM, resistente a rollback por reinicialização. `winbiovsmstorageadapter.dll` (que não importa `bcrypt.dll`/`crypt32.dll` diretamente, ao contrário da variante normal) é um shim que encaminha as operações sensíveis para dentro desse trustlet.

### Windows Hello Face: a câmera IR é tratada como câmera comum

`FaceBootstrapAdapter.dll` não é um motor de reconhecimento — é um orquestrador de descoberta/instalação (`CheckIfDeviceHasAFaceCapableCamera` → `FindSourceGroup` → `ComposeFaceVirtualDevice`). A câmera IR é descoberta como um **`MediaFrameSourceGroup`** do Windows Media Foundation, igual a qualquer câmera UVC — não como um barramento biométrico dedicado. O módulo também resolve/instala o driver INF mais adequado (`InboxDriverInstallationLogic` → `InstallTheBestHelloFaceDriver`) e depois compõe um "dispositivo biométrico virtual" exposto ao resto do framework pelas três interfaces padrão.

Anti-spoofing é enforced no nível do framework, não só no sensor: a propriedade `AccountAntiSpoofPolicy` e o símbolo `WinBioIsDeviceEnhancedSignInSecurityCapable` confirmam que o framework pode recusar resultados de dispositivos que não atendam ao nível "Enhanced Sign-in Security".

### Correção de rota: o engine real NÃO é do fabricante da câmera — é genérico Microsoft

A suposição original (de que o Engine Adapter de produção seria fornecido e assinado pelo fabricante da câmera) estava errada. Localizado em `DriverStore\FileRepository\helloface.inf_amd64_68853e1bbe6dfcb2\` — um pacote de driver inbox da própria Microsoft, sem qualquer vínculo com o fabricante do sensor IR (neste laptop, SunplusIT `2b7e:c757`). Isso confirma que **qualquer câmera IR "Windows Hello certified" é um sensor burro**: a Microsoft fornece o reconhecimento facial inteiro como software genérico, independente do hardware.

DLLs do pacote: `FaceProcessor.dll`, `FaceProcessorCore.dll`, `FaceRecognitionEngineAdapter.dll`, `FaceRecognitionSensorAdapter(Vsm/VsmSecure).dll`, `FaceTrackerInternal.dll`, `HelloFace.dll`, mais seis DLLs "Resources" (2–25 MB — tamanho incomum para recurso de idioma) que carregam os pesos do modelo.

**Pipeline de dois estágios, dois frameworks distintos:**

1. **Detecção** — `FaceProcessor.dll`/`FaceProcessorCore.dll` usam **ONNX Runtime** (`onnxruntime.dll` presente em `System32`). Strings confirmam: `Windows::Analog::Face::RetinaEngine::ProcessNextFrame`, `OnnxTesterRunInference`, `OnnxTesterGetOutputTensorData`, `NumPriorBoxesAndNumOutputTensorsMismatch`. O nome "RetinaEngine" + "prior boxes" é assinatura de detector por âncoras estilo **RetinaFace/SSD**. Detectores de oclusão (`FaceOcclusionDetector`, `MouthAndNoseOcclusionDetector`) também via ONNX (`LoadOnnxOcclusionModel`).
2. **Verificação (o embedding em si)** — `FaceRecognitionEngineAdapter.dll` **não usa ONNX**; usa uma lib de DNN proprietária interna, `DNNTestLib`, com nomenclatura de camadas estilo Caffe: `ConvLayer`, `FCLayer`, `PoolLayer` (Avg/Max), `DropoutLayer`, `SoftmaxLayer`, `FlattenLayer`, `ConcatLayer`, `PaddingLayer`, `LocalShareLayer` (camada localmente conectada, não convolucional), `AcrossChannelNormLayer`/`WithinChannelNormLayer`. O achado mais significativo é **`JointBayesianLayer`** — "Joint Bayesian" é a métrica de verificação facial de Chen et al. (ECCV 2012), característica de sistemas de 2014–2016 (ex. DeepID). Combinado com `LocalShareLayer`, a assinatura arquitetural é de uma rede **linhagem DeepID**: CNN extratora de features + métrica Joint Bayesian para decisão "mesma pessoa" — não uma rede moderna tipo ArcFace/FaceNet com embedding + distância cosseno/L2 pura, embora `FeatureDistanceCNN`, `BestMatchDistance`, `MinDistance`, `ComputeAngleDistance` também apareçam (caminho(s) de distância direta sobre as features, além do Joint Bayesian). Entrada tratada em escala de cinza (`BGRToGray`), coerente com a câmera IR deste laptop ser greyscale 8-bit.

RTTI expõe duas classes-template, `FaceVerificationCNN<FaceRecognitionCnnImpl>` e `FaceVerificationCNN<FaceRecognitionCnnImpl2>` — duas gerações/variantes do mesmo modelo entre versões do Windows.

**Pesos do modelo — localizados, não decodificados.** Embutidos como recurso PE de tipo nomeado `MODEL_FILES` nas DLLs "Resources": `FaceRecognitionEngineAdapterResources_v2.dll` (2 MB, 1 blob ≈1,99 MB) e `FaceRecognitionEngineAdapterResources_v5.dll` (25 MB, 2 blobs ≈12,37 MB e ≈12,40 MB — crescimento v2→v5 sugere evolução real do modelo, e v5 parecendo carregar dois modelos, possível ensemble ou detector+verificador separados). Cada blob abre com cabeçalho de 32 bytes cujo primeiro uint32 é `0x000AFACE` (soletra "A FACE" em hex — easter egg proposital da equipe). Tentativa de decodificar o restante como float32 foi descartada por evidência: magnitudes absurdas (1e-39 a 1e+37), byte mais significativo fora da faixa típica de pesos normalizados (0x3C–0x43), entropia de Shannon medida em 7,50 bits/byte (alta, mas não saturada/aleatória) — mais consistente com **pesos quantizados (int8/fixed-point)** do que float32 cru, plausível para um runtime proprietário leve de ~2015–2016.

**Dimensionalidade do embedding: não determinada.** `search_procedures` não retorna símbolos de função relevantes (`ComputeTemplate`, `FeatureDistanceCNN`, `TemplateSize` — vazio; binário stripado a nível de função, 5046 funções só por endereço). A função que referencia a string `MODEL_FILES` (0x18009da8b em `FaceRecognitionEngineAdapter.dll`) decompila para lógica de fallback/enumeração de 12 IDs de recurso com tratamento de HRESULT — não o parser de baixo nível do formato do blob. Determinar a dimensão exigiria decompilar o parser real de `DNNTestLib` que lê o blob `MODEL_FILES` (provavelmente um construtor de `FCLayer` ou `DNNTester::Evaluate` que lê um contador "num_output" dos próprios dados do modelo, não de uma constante fixa no binário) — não realizado nesta rodada.

### Critério de decisão "é a mesma pessoa": FAR calibrada (1 em 100.000), não distância bruta

Achado central (confirmado por decompilação + constante binária + schema de telemetria, todos convergentes): o Windows Hello Face **não** compara os embeddings por um corte de distância arbitrário (tipo "cosseno > 0.6"). O conceito nativo do sistema é **taxa de falso aceite (FAR)** calibrada.

- **Schema de telemetria TraceLogging/ETW** embutido em `.rdata` de `FaceRecognitionEngineAdapter.dll` (lido por `read_bytes` em torno de `0x180100000`/`0x1800f2680`) contém eventos `Windows::Analog::Face::CreateFaceRecognition.Succeeded/Failed` com campos — não valores, mas nomes de campo que já denunciam o modelo mental do sistema: `TargetFalseAcceptRate`, `ClosestFalsePositiveRate`, `ClosestFalsePositiveRateToOtherUsers`, `EnrollOnFailureThresholdToMatch`, `EnrollOnFailureThresholdToNotMatchOtherUsers`, `EnrollOnFailureRelaxedThresholdToMatch`, `VerificationTech`, `MatchedUserId`.
- **Constante numérica**: `search_bytes` pelo literal IEEE-754 float32 de `1e-05` (`AC C5 27 37` little-endian) acha exatamente **uma** ocorrência no binário, em `0x1800de370` (`.rdata`). Outros candidatos testados (`2e-5`, `1e-4`, `1e-6`, `0.001`) não aparecem.
- **Decompilação do consumidor**: `xrefs` de `0x1800de370` leva à função que contém `0x1800490b3` (`FUN_180048f1c`) — o laço central de comparação do candidato contra os templates ("prints") já enrolados do usuário. Inicializa busca de mínimo (`fVar25 = FLT_MAX`) e itera, pontuando cada template via chamada de vtable (offset `0x38`, plausivelmente o adapter Joint-Bayesian/CNN). A constante `1e-05` aparece em dois pontos de decisão: (1) num laço de até 24 slots (plausivelmente outros usuários/prints), marcando colisão quando `score < 1e-05` — bate com o campo `EnrollOnFailureThresholdToNotMatchOtherUsers`; (2) no gate final de aceitação, que exige `score_candidato <= 1e-05` E `score_segundo_melhor <= 1e-05` para autenticar.

**Conclusão**: a saída do verificador não é usada como "distância crua" — é convertida (pela chamada de vtable) numa probabilidade estimada de falso aceite, e a aceitação exige essa probabilidade abaixo de **1×10⁻⁵ (1 em 100.000)**. Bate com o número que a própria Microsoft divulga publicamente para Windows Hello Face ("menos de 1 em 100.000" de chance de um estranho desbloquear o aparelho) — aqui confirmado como constante real de decisão no binário, não apenas marketing.

**Limitação explícita**: não há evidência de um segundo valor numérico para o caminho ESS/VBS vs. legado — o campo de telemetria `EnrollOnFailureRelaxedThresholdToMatch` sugere a existência de um threshold "relaxado" em algum fluxo, mas esse valor não aparece como constante literal neste binário (pode ser calculado em runtime ou residir em outro módulo/VSM não inspecionado).

## Criptografia e formato de armazenamento dos templates

### Correção de rota: não é AES-GCM, é AES-256-CBC

A primeira rodada (sem decompilador) inferiu AES-GCM pela presença da string `ChainingModeGCM` em algum lugar do binário. A decompilação real de `winbiostorageadapter.dll` desmente isso para a cifra de registros do banco: a função de geração de chave (`crypto.cpp`) chama explicitamente `BCryptOpenAlgorithmProvider(L"AES")` → `BCryptSetProperty(L"ChainingMode", L"ChainingModeCBC")` → `BCryptGenRandom` (32 bytes de chave + 16 bytes de IV) → `BCryptGenerateSymmetricKey` → `BCryptExportKey(L"KeyDataBlob")`. As funções de cifrar/decifrar registro chamam `BCryptEncrypt`/`BCryptDecrypt` com `dwFlags=BCRYPT_BLOCK_PADDING` (PKCS7 — só existe em modo de bloco, nunca em AEAD/GCM). **Não há tag de autenticação própria desse primitivo.**

### Duas camadas de proteção de chave distintas (achado central, confirmado por decompilação)

A primeira rodada tinha fundido isso num único mecanismo de "envelope encryption com TPM". São dois mecanismos diferentes, em binários diferentes:

- **(a) Chave do banco de templates** (`winbiostorageadapter.dll`, `crypto.cpp`) — protegida com **Windows DPAPI puro**: `CryptProtectData(blob, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &protected)`, sem entropia opcional, sem TPM/NCrypt envolvido diretamente aqui. A proteção vem da cadeia padrão de DPAPI (ligada à conta/máquina), não de um selo TPM explícito nesta camada.
- **(b) `WinBioProtectData`/`WinBioUnprotectData`** (as funções públicas genéricas de "selar dados arbitrários", implementadas em `wbiosrvc.dll`, módulo `service\trustlet\lib\tpmpolicysession.cpp`) — **esta sim é a camada TPM de verdade**: `NCryptOpenStorageProvider(L"Microsoft Platform Crypto Provider")` → `NCryptOpenKey(hProv, hKey, L"MICROSOFT_PCP_KSP_RSA_SEAL_KEY_3BD1C4BF-004E-4E2F-8A4D-0BF633DCB074")` → concatena os buffers do chamador → `NCryptEncrypt` (RSA). Essa chave RSA selada no TPM tem **nome fixo e global** (mesmo GUID em qualquer instalação Windows Hello, não é por-usuário) e serve como primitivo genérico de "selar bytes arbitrários contra este chip" — não é usada diretamente para cifrar o banco de templates; é uma API à parte que outros componentes (ex. NGC) podem invocar.
- `StorageManagerImportReencrypt` confirma suporte a reencriptação do banco inteiro (troca de chave / migração de formato) — vale prever isso desde o v1 do open-hello.

O parsing do arquivo acontece dentro dos storage adapters (`storage_adapter\dll\{storageadapter,filemanager,crypto,purge}.cpp` + `storage_adapter_common\filelayout.cpp`, compartilhado pela variante VSM) — não em `WinBioDataModel.dll`, que é apenas um componente WinRT de data-binding para a UI de enrollment, sem lógica de arquivo.

### Formato do arquivo `.DAT` (confirmado por decompilação + aritmética exata de tamanho)

A função que cria o arquivo (`filemanager.cpp`, dentro de `CreateDatabase`) faz `CreateFileW(CREATE_NEW)` → `SetFilePointerEx(0x400)` → `WriteFile(header, 0x78 bytes)` em 0x400 → `FlushFileBuffers` → grava a chave AES-256+IV protegida por DPAPI (seção anterior) logo em seguida. Isso bate exatamente com o tamanho real do arquivo pequeno observado: **1144 bytes = 0x478 = 0x400 (header reservado) + 0x78 (bloco de chave/IV)**.

Layout confirmado:

```
[0x000, 0x030)  header de schema (lido por inspeção direta de bytes, rodada 1):
                  0x00  tag/versão de formato (0x156)
                  0x04  uint32 = 1
                  0x08  GUID de schema fixa {DF9D8CD0-1501-11D1-8C7A-00C04FC297EB} — igual em todo arquivo
                  0x18  uint32 = 1
                  0x1C  GUID de instância (varia por arquivo/database)
[0x030, 0x400)  reserva/padding até completar 1024 bytes
[0x400, 0x478)  bloco de 120 bytes: KeyDataBlob (chave AES-256 exportada) + tamanho do IV (ULONG em 0x44) + 16 bytes de IV (em 0x68) — tudo protegido por CryptProtectData antes de ir para disco
[0x478, EOF)    só presente no arquivo grande (820 KB) — registros individuais via StorageAdapterAddRecord:
                  header fixo de identidade (10 QWORDs, prováveis campos de WINBIO_IDENTITY/GUID/SID)
                  + tamanho do ciphertext (campo próprio no registro)
                  + payload cifrado (AES-256-CBC, mesma chave do bloco 0x400–0x478)
                  + possível blob variável adicional
```

**Não resolvido nesta rodada**: o destino exato do blob DPAPI dentro dos 1024 bytes reservados (função não decompilada por orçamento), e se há mais de um registro por arquivo grande ou um índice separado.

## Camada 3 — NGC e logon

### O que é NGC

Uma chave assimétrica por usuário/dispositivo, gerada e mantida localmente, nunca derivada de senha, que substitui a senha como segredo de autenticação. Confirmado por:

- `ngcksp.dll` exporta `GetKeyStorageInterface` (contrato de CNG Key Storage Provider) com símbolos `KspCreatePersistedKey`, `KspSignHash`, `KspDecrypt`, `KspDeriveKey`, `KspSecretAgreement`, registrado como `Microsoft.Windows.Security.NGC.KspSvc`.
- `ngcutils.dll` exporta `NgcIsInsecureTpm` (checagem explícita de TPM inseguro) e há suporte a atestação da chave perante o TPM via AIK (`ContainerGetAikCertificate`, em `ngcsvc.dll`).
- Existe fallback por software (`Microsoft Software Key Storage Provider`) quando não há TPM, mas o caminho padrão é hardware — `NgcProCsp.dll` é o CSP legado equivalente para apps pré-CNG.

### Container NGC e "Protector"

`NgcCtnr.dll` expõe (via COM) as operações sobre o container: `ContainerCreate/Load/Unload`, `ContainerSignHash`, `ContainerDecryptPkcs1`, `ContainerDeriveKey`, `ContainerSecretAgreement`, `ContainerGetAikCertificate`, e a abstração central — `ContainerAddProtector`/`ContainerChangeProtector`/`ContainerIsProtectorAuthenticated`. Um **Protector** é qualquer fator que autentica para usar a chave: PIN é um Protector, biometria é outro, intercambiáveis sobre o mesmo container. PIN tem *soft lockout* (`ContainerGetSoftLockoutInfo`) — limite de tentativas com backoff.

`NgcCtnrSvc.dll` arbitra entre duas implementações de container, visíveis nos próprios símbolos: `CoCreateInstanceNgcCtnrContainer` (forte, TPM/isolada) vs. `CoCreateInstanceNgcCtnrContainerSoftware` (fallback).

### A ponte exata biometria→AuthValue (confirmado por decompilação Ghidra)

A primeira rodada (sem decompilador) só conseguiu inferir que `wbiosrvc.dll` tinha um módulo `ngc.cpp`/`authvalue.cpp` fazendo essa ponte. A decompilação real revelou que a ponte é mais fina do que o esperado: **`wbiosrvc.dll` não implementa a lógica criptográfica do AuthValue**. A função que implementa a RPC pública `WinBioNgcAuthorizeEnrollment` (módulo `service\server\ngc.cpp`) faz só isto:

```
ConvertSidToStringSidW(identity.AccountSid, &sidString)
RpcImpersonateClient(bindingHandle)     // assume o contexto de segurança do chamador
NgcAddBioProtector(sidString, enrollmentHandle, CONST_GUID /* tipo de protector "biometria" */)
RpcRevertToSelf()
```

Ou seja: `wbiosrvc.dll` é só um **portão RPC autenticado** — converte a identidade local (SID) para string, impersona o chamador por chamada (mesmo padrão de autorização visto em todo o resto do serviço), e delega inteiramente para `NgcAddBioProtector`, uma função exportada por `cryptngc.dll`.

**A cadeia continua, confirmado por decompilação de `cryptngc.dll`**: `NgcAddBioProtector` (export resolvido) é majoritariamente boilerplate de tracing ETW; a lógica real está atrás de dois saltos finos (`FUN_180031f8c` → `FUN_18003d638`) que só repassam os três parâmetros recebidos (SID, handle de enrollment, GUID do tipo de protector) sem tocá-los, constroem um security descriptor SDDL `D:(A;;GR;;;SY)` (leitura restrita a `SYSTEM`) e despacham via um stub RPC gerado por MIDL. O caminho de código-fonte embutido confirma isso sem ambiguidade: `onecore\ds\security\ngc\kspsvc\mgmt\ngcmgmtrpcclient.cpp` — **`cryptngc.dll` é, ela mesma, só mais um cliente RPC**, desta vez para o serviço de gerência NGC (`kspsvc`).

**Elo final resolvido por decompilação — geração real do segredo**: `NgcCtnr.dll` expõe `ContainerAddProtector` só como string de metadado ETW, sem lógica própria acessível (é puramente uma fachada COM). A implementação de verdade está em `NgcCtnrSvc.dll` (o serviço broker), localizada não por nome (sem xref resolvido a partir da string `"CreateBioProtectorAddProtector"`) mas por comportamento — seguindo o uso de `BCryptGenRandom` em 6 saltos até a função central `FUN_180075644`:

- Gera **dois valores aleatórios independentes de 20 bytes cada** via o provider RNG do CNG.
- Configura um objeto "builder" com metadados de tipo/política (chamadas tipo `(builder, 0xc1, 0xb)`, `(builder, 1)`, `(builder, 0x40000000)` — significado exato dos códigos não decodificado), depois lê de volta dois outros valores de 20 bytes desse builder (prováveis campos derivados de uma política TPM, não confirmado).
- Concatena um dos valores lidos + o segundo aleatório (40 bytes) e computa um **HMAC-SHA1 manuscrito** (construção clássica ipad/opad, confirmada passo a passo no pseudocódigo) sobre esse bloco — o resultado de 20 bytes é o campo de ligação final do registro do Protector.
- Monta um registro de saída (tipo + dois aleatórios + dois valores do builder + flag fixo + HMAC) e **zera todos os buffers sensíveis antes de retornar**.

**Conclusão**: o AuthValue/Protector biométrico **não é um segredo TPM opaco — é um valor aleatório gerado em software** (via CNG `BCryptGenRandom`), acompanhado de um segundo aleatório e de um HMAC-SHA1 de ligação entre eles, empacotados num registro que o builder grava/associa ao container. Nenhuma chamada a `NCrypt`/TPM foi encontrada diretamente nesta função — se há selagem por TPM, ela acontece numa camada mais externa (o builder resultante pode ser repassado a uma API TPM fora do escopo decompilado). **Resumo da cadeia completa, do pedido de enrollment até a geração do segredo**: `winbio.dll` (cliente) → RPC → `wbiosrvc.dll::ngc.cpp` (impersonation + SID) → RPC → `cryptngc.dll::ngcmgmtrpcclient.cpp` (SD + GUID) → RPC → `NgcCtnrSvc.dll` → `FUN_180075644` (geração do segredo real: 2× 20 bytes aleatórios + HMAC-SHA1). **Não resolvido**: o significado exato dos dois campos lidos do builder (possível ligação com política TPM) e o destino do registro montado após o retorno desta função.

### Isolamento da chave (trustlet NGC)

A implementação forte roda fora do kernel normal:
- `NgcIso.exe` é um trustlet IUM (exporta só `__ImagePolicyMetadata`, assinatura clássica de processo autorizado pelo Secure Kernel em VTL1).
- `NgcIsoCtnr.dll`, carregado dentro desse trustlet, reimplementa a superfície de container com prefixo `NgcIsoContainer*`, mais um pool de pré-geração de chaves (`NgcIsoCtnrInitializePregenPool`, `NgcIsoCtnrTriggerPregen`) para reduzir latência no logon.

A operação criptográfica sensível (assinar/decifrar com a chave privada) acontece dentro da VTL1; o mundo normal (`NgcCtnrSvc.dll`) só encaminha RPC e nunca vê a chave privada em claro.

### Achado de design notável: o container se apresenta como smart card GIDS

`NgcCtnrGidsHandler.dll` revela, sem ambiguidade (strings: `"Microsoft simulated GIDS smart card"`, `GidsApplication`, `ElementaryFileIdentifier`, `GetSCardKeyContainerName`), que o container NGC se apresenta ao resto do Windows como um **smart card virtual GIDS** (Generic Identity Device Specification). A Microsoft não criou um tipo de credencial novo do zero — reaproveitou toda a pilha já existente de logon por smart card (minidriver, PKINIT do Kerberos) fazendo o container NGC falar o protocolo de um cartão GIDS por software. Uma única pilha de "logon com chave assimétrica" serve tanto cartão físico quanto TPM virtual.

### Credential Provider: a ponte entre biometria e NGC

`facecredentialprovider.dll` e `fingerprintcredential.dll` são DLLs COM puras (só exportam `DllGetClassObject`/`DllCanUnloadNow`), implementando a interface pública `ICredentialProvider`/`ICredentialProviderCredential` do LogonUI. Nomes de método internos confirmam isso literalmente: `FaceProvider::Advise`, `FaceCredential::GetSerialization`.

A ponte com a camada WinBio é uma classe interna `FaceBioListener`, com um fluxo assíncrono orientado a evento: `Initialize` → `Advise`/`RenewWinBioTicket` → `SessionCallbackHandler` → `ProcessWinBioRecognizeResult` (mais tratamento de estado de câmera e bloqueio por política de grupo). `fingerprintcredential.dll` é mais simples: usa polling síncrono direto via `WinBioGetCredentialState` — **Face usa modelo assíncrono orientado a sessão (câmera IR contínua); impressão digital usa polling de estado simples (sensor já entrega resultado pronto)**.

Em caso de sucesso, a serialização final da credencial é delegada a `ngckeyenum.dll`, que expõe serializadores por tipo (`NgcSerializeKeyCredential`, `NgcSerializeKeySspiCredential`, `NgcSerializeSmartCardCredential`, `NgcSerializePasswordCredential`) e `NgcCredProvEnumLogonKeys` (lista chaves de logon disponíveis do usuário). Qualquer Credential Provider biométrico, após confirmar identidade, delega a esse módulo a tarefa de transformar "posse da chave NGC desbloqueada" em um pacote de autenticação reconhecido pela LSA — na prática equivalente a um logon por smart card/PKINIT.

### PIN como fallback

`cngcredui.dll` não é um Credential Provider próprio — é uma DLL de UI compartilhada (caminhos-fonte confirmam `biopinhelper.c`, `bioinfo.cpp`, `cngcredui.cpp`) chamada tanto pelo fluxo de PIN quanto pelo de biometria. PIN e biometria são dois Protectors diferentes sobre o mesmo container — não dois sistemas paralelos. `ngcrecovery.dll` implementa recuperação de PIN perdido com um segredo de recuperação separado (`NgcProtectPinRecoverySecret`, `NgcRecoverPinSilent`), sem precisar reemitir a chave inteira.

### UserConsentVerifier (WinRT) — porta de entrada para apps de terceiros

`Windows.Security.Credentials.UI.UserConsentVerifier.dll` expõe a classe WinRT pública `UserConsentVerifier` (`RequestVerificationAsync(mensagem)`, retorno `UserConsentVerificationResult`). Não fala com WinBio diretamente — aciona por trás um prompt de UI de consentimento elevado que consulta o container NGC do usuário. É a forma de um app pedir "confirme que é você" sem nunca enxergar template biométrico nem chave.

## Fluxo fim-a-fim consolidado

```
Câmera IR / leitor de digital
        │  captura (Sensor Adapter) + matching local (Engine Adapter) — nunca sai da máquina
        ▼
WinBio Engine/Adapter ── resultado: match/no-match + ticket de sessão
        │
        ▼
Credential Provider (facecredentialprovider.dll / fingerprintcredential.dll)
   FaceBioListener::ProcessWinBioRecognizeResult (ou WinBioGetCredentialState p/ digital)
        │  sucesso → GetSerialization
        ▼
ngckeyenum.dll
   NgcCredProvEnumLogonKeys → identifica o container NGC do usuário
   NgcSerializeKeyCredential / NgcSerializeKeySspiCredential → monta o blob de logon
        │
        ▼
NgcCtnrSvc.dll (broker, mundo normal) ──RPC──▶ NgcIso.exe (trustlet VTL1)
   ContainerIsProtectorAuthenticated → marca o Protector "biometria" como satisfeito
   NgcIsoContainer* assina/decifra com a chave privada DENTRO da VTL1, via ngcksp.dll/TPM
        │  chave nunca deixa a secure world em claro
        ▼
Pacote de autenticação equivalente a smart card/PKINIT (via NgcCtnrGidsHandler.dll)
        │
        ▼
LSA valida o pacote como faria com um smart card físico
        │
        ▼
Sessão do Windows desbloqueada
```

## Mapeamento de design para o open-hello (Linux)

### Essencial replicar (núcleo conceitual, portável)

1. **Biometria nunca é o segredo** — é o destravador local de uma chave assimétrica selada em TPM 2.0. Mapeamento direto: `tpm2-tools`/`tpm2-pkcs11`, chave criada sob um primary key selado no TPM, com política de autorização satisfeita por um daemon de biometria após matching local.
2. **Separação em três camadas com contrato de função única por plugin** (Sensor/Engine/Storage) — em Linux, `dlopen`/`dlsym` sobre `.so` cumpre o mesmo papel que a vtable C do WinBio. Fácil de replicar 1:1.
3. **Conceito de "Protector" desacoplado da chave** — PIN e biometria como métodos intercambiáveis de liberar o mesmo uso de chave, com *soft lockout* por tentativas. Em TPM2: `TPM2_PolicyAuthValue` para PIN + satisfação externa da política após verificação biométrica.
4. **Arquitetura de dois daemons**: um para biometria (captura + matching local, nunca produz nem transmite "senha") e um para chave/credencial (só recebe resultado binário + ticket de sessão) — preserva o isolamento de responsabilidade que o Windows mantém entre WinBio e NGC.
5. **Anti-brute-force contabilizado fora do SO** (no TPM, resistente a rollback por reinicialização) — não pular essa parte; é a principal defesa contra ataque offline ao template/chave.
6. **Câmera IR tratada como câmera de vídeo comum** — no Linux, a câmera IR de notebooks com suporte a Windows Hello tipicamente já aparece como `/dev/videoN` adicional (V4L2), evitando reinventar driver de biometria dedicado.
7. **Cifra do banco de templates com integridade separada da confidencialidade**: o Windows usa AES-256-CBC (não GCM) para o payload e DPAPI para proteger a chave da sessão — ou seja, não há tag de autenticação própria do primitivo. Para o open-hello, vale fazer melhor: usar um modo AEAD real (AES-256-GCM ou ChaCha20-Poly1305) para já sair com confidencialidade + integridade no mesmo primitivo, em vez de replicar a lacuna do Windows. Formato de arquivo versionado desde o início (o Windows já suporta reencriptação/migração — vale prever isso no open-hello).

### Específico de Windows, precisa de equivalente diferente em Linux

1. **VBS/Isolated User Mode (trustlet + hypervisor Hyper-V)** — não existe equivalente direto em Linux estoque. Alternativas pragmáticas: confiar no isolamento do próprio TPM discreto (a chave já não sai do chip, de qualquer forma — o valor do IUM é proteger contra side-channels do kernel host, não substituir o TPM), ou um TEE de hardware (Intel SGX/TDX, ARM TrustZone/OP-TEE) se o projeto quiser esse nível. Para v1, um daemon dedicado com namespace/seccomp estrito é uma aproximação razoável e honesta (documentar que é um isolamento mais fraco).
2. **Smart card GIDS virtual / PKINIT** — truque de integração específico do ecossistema LSA/Kerberos do Windows. Em Linux, o ponto de integração equivalente é um módulo **PAM** dedicado (`pam_open_hello.so`) ou um provedor **PKCS#11** consumido por `pam_pkcs11`/OpenSC, em vez de inventar um novo tipo de credencial.
3. **RPC local (ncalrpc/ALPC) com impersonation por chamada** — em Linux, socket Unix com `SO_PEERCRED` cumpre o mesmo papel de autorização por chamada, sem precisar do aparato NDR completo.
4. **LSA/LogonUI como barramento central de pacote de logon** — não existe em Linux. Ponto de integração natural: pilha PAM (`auth`/`account`) para desbloqueio de sessão local; D-Bus/polkit como equivalente ao `UserConsentVerifier` para apps pedirem confirmação biométrica pontual sem logon completo.
5. **Validação de nível de assinatura de plugin (Code Integrity)** — pode virar checagem de permissão de arquivo/capability simples em v1.
6. **Integração com Power Dependency Coordinator** — equivalente em Linux: hooks em `systemd-logind`/`upower` para suspend/resume.
7. **Device Credential ligado a Azure AD/Entra** (`DeviceCredentialTpmHmac`) — fora de escopo a menos que o projeto também mire *device trust* corporativo.

## Próximos passos sugeridos

Concluído (Ghidra 12.1.4 configurado e usado em três rodadas):
- Formato exato do `.DAT` e sequência criptográfica de `crypto.cpp` (AES-256-CBC + DPAPI, separado da chave RSA-TPM genérica de `WinBioProtectData`).
- **Cadeia completa do AuthValue, do cliente até a geração do segredo**: `winbio.dll` → `wbiosrvc.dll::ngc.cpp` (impersonation+SID) → `cryptngc.dll::ngcmgmtrpcclient.cpp` (SD+GUID, mais um repasse) → `NgcCtnrSvc.dll` (geração real: dois aleatórios de 20 bytes via `BCryptGenRandom` + HMAC-SHA1 de ligação). Achado relevante para o design: **o Protector biométrico não depende de uma operação criptográfica do TPM para ser criado** — é software puro (CNG RNG + HMAC); o TPM entra em outro lugar da arquitetura (selagem da chave NGC em si, já documentada acima), não na criação do Protector.
- Pipeline de captura (`CWinBioSrvCaptureSample::Execute`): validação de sessão, arbitragem de lock, resolução do adapter bundle, e os dois caminhos de disparo (Sensor Adapter direto vs. Sensor+Engine Adapter em dois estágios).
- Localização de `EnrollCommit` e confirmação de que ele faz checagem de consistência de fator biométrico antes de qualquer gravação — mas sem isolar com certeza qual sub-chamada é o Storage Adapter.

Pendente (detalhe residual, não bloqueante para o design do open-hello — a arquitetura macro já está fechada):

- O significado exato dos dois campos lidos do "builder" em `NgcCtnrSvc.dll` antes do HMAC (possível ligação com política TPM) e o destino do registro do Protector após essa função retornar.
- Isolar, dentro de `EnrollCommit`, qual das três sub-chamadas pós-checagem-de-fator é especificamente o Storage Adapter gravando o blob cifrado (vs. transições de estado do Engine Adapter). `Identify`/`Verify` nem chegaram a ser localizadas.
- Decidir o nível de isolamento alvo para a v1 (TPM simples vs. TEE) antes de desenhar o protocolo entre o daemon de biometria e o daemon de chave.
- Mapear hardware disponível: verificar se a câmera IR do notebook aparece como `/dev/videoN` com V4L2, e se há suporte de leitor de digital via `libfprint`.
