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
