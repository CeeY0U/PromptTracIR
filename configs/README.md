# Attribution settings

`attribution-defaults.json` is `ptir config` output: every weight, threshold and time window the
attribution engine uses, at its built-in default. A test fails if it drifts from
`prompttracir/config.py`, so this file always shows what an unconfigured `ptir analyze` does.

## Tuning

1. Copy only the keys you want to change into a new file, e.g. `configs/attribution-v0.4-tuned.json`:

   ```json
   {"_note": "tuned on families legitimate, data_transmission, persistence (training split), 2026-11-20",
    "decision_margin": 1.0,
    "calibration_temperature": 2.0}
   ```

   Keys starting with `_` are comments. Unknown keys are rejected.

2. Score the **training** families only, with the candidate settings:

   ```bash
   ptir eval-batch runs --reviewed-only --families legitimate,data_transmission,persistence \
       --config configs/attribution-v0.4-tuned.json --tag tune-01
   ```

   Each run is re-analysed into `output/tune-01/`; the report goes to `runs/results/tune-01/`.
   Compare attribution macro-F1, abstention and calibration (ECE) across tags.

3. When you settle, commit the file, and score the **test** families once:

   ```bash
   ptir eval-batch runs --reviewed-only --exclude-families legitimate,data_transmission,persistence \
       --config configs/attribution-v0.4-tuned.json --tag final-test
   ```

   Report those numbers with the file's fingerprint (`config.json` in each output folder, and
   `condition.config_fingerprints` in `results.json`). Do not tune again after looking at them.

# Local model (v0.6)

`local-model.json` pins the model the lab agent's real runs and PromptTracIR's local-model
analysis use: Qwen2.5-7B-Instruct, Q4_K_M, served by llama.cpp's `llama-server`, and the sampling
settings for analysis (temperature 0, seed 1234, at most 1024 tokens per reply). `ptir llm-pin`
prints it; `ptir analyze --llm-url` and `ptir explain` read it, and every `llm.json` records it
next to the model id the server reported, so a result can be traced to the model that produced
it. Fill in `model.sha256` once from the lab VM (`Get-FileHash C:\tools\llama\model.gguf`).
