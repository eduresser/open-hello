# Avaliação de acurácia

Mede, fora da aplicação, quantas vezes o reconhecimento aceita a pessoa certa e rejeita outras. A aplicação continua toda em Rust; esta pasta só lê o que ela produz (`openhello-calibrate`) e roda os mesmos modelos ONNX.

## Escopo

- Roda YuNet e AuraFace em Python, com o mesmo pré-processamento do Rust (letterbox 640, alinhamento ArcFace de 5 pontos, cinza replicado em 3 canais).
- Lê o arquivo de calibração gerado pelo Rust e aplica os limiares de produção: meta de FAR dividida pelo número de embeddings do template (verify) ou de todos os templates (identify).
- Não calibra nada por conta própria. Quem calibra é o `openhello-calibrate`.

## Ambiente

```bash
cd evaluation
uv sync
uv run pytest
```

## Fluxo com o LFW

Datasets ficam fora do repositório (`data/` está no `.gitignore`).

```bash
uv run python -m openhello_eval prepare --parquet lfw.parquet --out data/people
uv run python -m openhello_eval embed --models-dir MODELS --images-dir data/people --out data/embeddings.npz
uv run python -m openhello_eval strangers --images-dir data/people --out data/strangers
openhello-calibrate --models-dir MODELS --images-dir data/strangers --out data/calibration.bin
uv run python -m openhello_eval parity --images-dir data/people --embeddings data/embeddings.npz --calibration data/calibration.bin
uv run python -m openhello_eval report --images-dir data/people --embeddings data/embeddings.npz --calibration data/calibration.bin
```

`MODELS` é a pasta com `yunet.onnx` e `glintr100.onnx`. O ONNX Runtime do Python vem do `uv`; o `openhello-calibrate` precisa de `ORT_DYLIB_PATH`.

## Divisão das identidades

- Com pelo menos `enroll-shots + 2` fotos: cadastradas. As primeiras `enroll-shots` fotos formam o template e as demais são tentativas.
- Com menos fotos: estranhos. A primeira foto de cada um calibra o FAR e serve de rosto não cadastrado na identificação.

## Paridade com o Rust

- `parity` compara os quantis da tabela de calibração gerada pelo Rust com os quantis que o Python calcula dos próprios embeddings. Diferença acima de 0,02 ou número de pares diferente falha o comando.
- `tests/test_calibration.py` confere o cálculo de limiares contra `crates/engine-adapter-face/tests/fixtures/calibration_golden.json`, o mesmo arquivo que o teste Rust confere.
- Regenerar o arquivo de referência: `cargo test -p engine-adapter-face --lib regenerate_golden -- --ignored`.

## Notebook

`notebooks/evaluation.ipynb` usa as mesmas funções e plota distribuições, FAR medido contra a meta e curva ROC. Commitar sem saídas. Para regenerá-lo: `uv run python notebooks/build_notebook.py`.

```bash
OPENHELLO_EVAL_DATA=data uv run jupyter lab
```

## Limites

- O LFW é luz visível. Isto mede o pipeline, não o desempenho em infravermelho (ASM-001).
- Há alguns erros de rótulo no LFW, que inflam levemente os impostores.
