# AGENTS.md — JEV Attack Surface Analysis

How an agent runs the analysis and reads its output. Method and design: `README.md`.

## Run

```bash
source ~/.secrets.sh   # loads TYPESAFE_API_KEY
.venv/bin/python attack_surface_scan.py <repo_path> --budget 0.03   # venv: pip install -r requirements.txt
```

- `<repo_path>`: a Python, JavaScript or TypeScript repo, usually cloned into `repos/` (git-ignored).
- `--budget`: max USD for the run. Keep it ≤ `max_run_budget_usd` in `classification_levels.json` (0.05).
  A ~150-function repo costs about $0.01.
- Output: `examples/<repo name>/scan_result.json` (latest) and `examples/<repo name>/runs/<run id>.json` (history), plus `progress.log` next to it (tail it while running).
- Prints one JSON line per level when it finishes it, then `spent $X of $Y -> <path>`.

## Get the issues

```bash
python print_issues.py examples/<repo>/scan_result.json [--file <path>] [--top N]
```

Prints the validation instruction plus a numbered list, hottest first:

```
1. introduction/views.py:158 sql_lab() [unsafe input to sink, heat 1.00]
   sql_query = "SELECT * FROM introduction_login WHERE user='"+name+"' ...
```

These are candidates ranked by a classifier. Validate each one; do not fix code unless the user asks.

## scan_result.json

```
{repo, run: {id, started_at, tool_version, levels_sha256}, budget_usd, spent_usd,
 levels: [{name, units_found, units_classified, units_passed, spent_usd, budget_usd, measured_over_estimated_tokens}],
 nodes:  [{level, path, name, line, size, heat, passed, answer, tokens, estimated_tokens}]}
```

- `level`: `directory` | `file` | `function` | `line`.
- `heat`: 0..1, higher = more suspicious. `passed`: went on to the next level.
- `answer`: jev's probabilities per category; for `line` nodes, a list of `{line, code, probability}`.
- An issue = a `function` node with `passed: true`; its `line` node (same `path` and `line`) locates it.

## Viewer

`python viewer_server.py` → http://localhost:7801/heatmap_viewer.html (port in the command, default 7801).
The user runs and inspects it; agents use the commands above.
