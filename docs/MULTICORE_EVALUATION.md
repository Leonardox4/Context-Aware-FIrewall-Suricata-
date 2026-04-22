# Multi-Core Runtime Scoring — Evaluation Report

**Date:** 2025  
**Scope:** Model2 hybrid ML firewall — Isolation Forest, Random Forest, runtime_scoring.py  
**Goal:** Determine why runtime scoring uses ~1 CPU core and whether multi-core execution is feasible and beneficial.

---

## 1. Inspection Summary

### 1.1 Model instantiation (training)

| Component | File | n_jobs at instantiation |
|-----------|------|--------------------------|
| Isolation Forest | `models/isolation_forest_model.py` | **`n_jobs=-1`** (line 19) |
| Random Forest | `models/random_forest_model.py` | **`n_jobs=-1`** (line 20) |

Both models are **already** built with `n_jobs=-1` in the codebase. No change was required in model constructors.

### 1.2 Training scripts

- **`training/hybrid_training_pipeline.py`**: Calls `build_isolation_forest(...)` and `build_random_forest(...)` with no override of `n_jobs`. So trained models get `n_jobs=-1` from the module defaults.
- **`training/stream_suricata_training.py`**: Calls `build_isolation_forest(...)` and `build_random_forest(...)`; same as above.

### 1.3 Artifact save/load

- **`utils/serialization.py`**: Uses `joblib.dump(if_model, ...)` and `joblib.load(...)`. Estimator attributes (including `n_jobs`) are pickled and restored. **Artifacts are backward compatible**; loading does not re-fit the scaler or change model parameters.

### 1.4 Runtime scoring

- **`inference/runtime_scoring.py`**: Loads artifacts once in `load_models()`, then for each chunk calls `score_chunk()` which:
  - `scaler.transform(X)` — no fit, single-threaded in sklearn StandardScaler.
  - `if_model.decision_function(X_scaled)` — see §2.
  - `rf_model.predict_proba(X_scaled)` via `attack_probability()` — see §2.
  - Risk computation and decision loop — pure Python/numpy, single-threaded.

Chunk streaming, JSONL writing, and gc are unchanged; no accumulation of results in memory.

---

## 2. Sklearn Inference Parallelism

### 2.1 RandomForestClassifier

- **Source:** `sklearn/ensemble/_forest.py` (predict_proba path).
- **Behavior:** Uses `n_jobs, _, _ = _partition_estimators(self.n_estimators, self.n_jobs)` and `Parallel(n_jobs=n_jobs, ...)` to distribute tree predictions across jobs. **Inference does use `self.n_jobs`** (and hence benefits from `n_jobs=-1` when loading from joblib).

### 2.2 IsolationForest

- **Source:** `sklearn/ensemble/_iforest.py` (`_compute_score_samples`, used by `decision_function`).
- **Behavior:** The prediction path calls `Parallel(verbose=self.verbose, require="sharedmem")` **without** passing `n_jobs`. So joblib uses its default (typically 1 job). The in-code comment states that the default is intentional for small sample sizes; parallelism can be overridden only via `joblib.parallel_backend` around the call. **IsolationForest inference is effectively single-threaded in sklearn**, regardless of the estimator’s `n_jobs` attribute.

### 2.3 Summary

| Model | Training parallel? | Inference parallel? | Controlled by our n_jobs? |
|-------|--------------------|---------------------|----------------------------|
| Isolation Forest | Yes (fit uses n_jobs) | **No** (sklearn does not pass n_jobs in predict) | No at inference |
| Random Forest | Yes | **Yes** (predict_proba uses self.n_jobs) | Yes at inference |

---

## 3. Why You Might Still See Single-Core Usage

Even with RF using `n_jobs=-1` at inference, possible reasons for ~1 core usage:

1. **Artifacts from older code:** If artifacts were trained with an older version of the code that did not set `n_jobs=-1` for RF, the loaded RF would have `n_jobs=None` (or 1) and inference would be single-threaded. **Retraining with the current code** would then be required so that the saved RF has `n_jobs=-1`.
2. **I/O / parsing bottleneck:** JSONL parsing, pandas normalization, and file I/O run in the main thread. For large eve.json files, a large fraction of time can be spent in parsing and normalization; in that case CPU usage is dominated by one thread and model inference is a smaller share. Enabling more cores in the model helps only the inference part.
3. **Chunk size:** If chunks are small (e.g. a few thousand rows), the overhead of joblib parallelization can outweigh the benefit, and sklearn/joblib may effectively run with few workers.
4. **Environment:** `JOBLIB_N_JOBS` or other joblib/OpenMP settings can limit effective parallelism.

---

## 4. Answers to Evaluation Questions

- **Were IF and RF trained with n_jobs?**  
  **Yes.** Both are built with `n_jobs=-1` in `models/isolation_forest_model.py` and `models/random_forest_model.py`.

- **Is parallelism already enabled but not used?**  
  **Partially.** RF inference uses `n_jobs` (so with current code and artifacts it can use multiple cores). IF inference in sklearn does **not** use `n_jobs`; it is single-threaded by design in the prediction path.

- **Is inference limited by sklearn internals?**  
  **For IF, yes** — the predict path does not pass `n_jobs` to `Parallel`. For RF, no; inference is parallel when `n_jobs=-1` on the loaded model.

- **Is JSON parsing the real bottleneck?**  
  **It can be.** For large JSONL files, parsing and normalization often dominate runtime. Multi-core model inference then improves only the scoring part of the pipeline.

- **Would enabling n_jobs=-1 materially improve inference speed?**  
  **Already enabled** in code. For **RF**, it can improve inference speed if (1) artifacts were trained with this setting and (2) inference time is a significant share of total runtime. For **IF**, changing our code does not help inference; only a different sklearn version or using `parallel_backend` around the IF call could change that (with possible trade-offs).

---

## 5. Feasibility and Recommendations

### 5.1 Multi-threading / multi-core feasibility

- **Random Forest:** Multi-core inference is **feasible and already configured** via `n_jobs=-1`. No code change needed; ensure artifacts are trained with current code so the saved RF has `n_jobs=-1`.
- **Isolation Forest:** Multi-core **inference** is **not** under our control; sklearn’s IF predict path is single-threaded. Training remains parallel.

### 5.2 Which components benefit

- **RF inference:** Benefits from `n_jobs=-1` (already set) when artifacts carry it.
- **IF inference:** No benefit from our `n_jobs` at inference; bottleneck is sklearn implementation.
- **Scaler:** transform is single-threaded; no change.
- **Parsing / I/O:** Would require separate design (e.g. parallel chunk reading) and is out of scope for “model n_jobs” changes.

### 5.3 Expected speed gain

- **Rough estimate:** If RF inference is, say, 30–40% of total runtime, parallelizing it (e.g. 4 cores) might yield up to ~10–20% end-to-end improvement, depending on chunk size and hardware. If parsing dominates, gain will be smaller.

### 5.4 Risks

- **Memory:** joblib typically uses process-based parallelism (loky); each worker may use extra memory. With chunk-based processing and no accumulation, overall memory impact is usually modest.
- **Instability:** Rare; joblib is widely used. If issues appear, set `JOBLIB_N_JOBS=1` or pass `n_jobs=1` to RF to force single-threaded inference.
- **Contention:** With many workers and small chunks, overhead and contention can reduce or negate gains.

### 5.5 Retraining and artifacts

- **Retraining:** Required **only if** current artifacts were produced by code that did not set `n_jobs=-1` for RF. Then retrain so the saved RF has `n_jobs=-1` and inference can use multiple cores.
- **Artifacts:** No need to regenerate artifacts if they were already trained with the current model code (both IF and RF built with `n_jobs=-1`). Backward compatibility is preserved; loading does not re-fit scaler or change n_jobs.

---

## 6. Phase 2 Implementation (Done)

Given the above:

1. **No change to training scripts** — IF and RF already use `n_jobs=-1`.
2. **Startup logging** added in runtime_scoring: CPU count and model `n_jobs` so you can confirm RF has `n_jobs=-1` and see core count.
3. **Documentation** updated: threading/parallelism behavior, that IF inference is single-threaded in sklearn, that retraining is only needed if artifacts are old, and performance tuning notes.

No Python threading was introduced; chunk streaming and memory safety are unchanged.
