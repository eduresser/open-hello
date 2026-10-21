# Fixtures de quadros IR

Quadros infravermelhos gravados da câmera do próprio desenvolvedor, usados pelos testes sem câmera ao vivo.

## Regras

- Somente quadros da câmera do desenvolvedor. Nunca datasets de terceiros (licenciamento).
- Datasets NIR públicos servem apenas para calibração de FAR offline e local; ficam fora do repositório.
- Cada pessoa é um diretório `tests/fixtures/<identidade>/` com quadros `NNN.pgm`.
- Formato: PGM binário (`P5`), 8 bits, escala de cinza, resolução nativa do nó IR.
- Capturas de pessoas além do desenvolvedor exigem consentimento escrito e não entram no git sem ele.

## Formato esperado

`tests/support/frame_fixtures.rs` lê e grava esse formato (`read_pgm`, `write_pgm`, `load_identity`, `load_all_identities`).

## Como gravar

1. Descobrir o payload do emissor IR com `linux-enable-ir-emitter` (ASM-004) e exportar `OPENHELLO_IR_EMITTER=unidade:seletor:payloadhex`.
2. Usar `Sensor Adapter` (`sensor-adapter-ir`) para capturar quadros e gravá-los com `write_pgm`.
3. Variar pose (yaw de -45° a 45°) e iluminação.
