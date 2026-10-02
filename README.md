# JEV Attack Surface Analysis

Point it at a Python repo and a budget in dollars. You get a ranked list of the places an
attacker would look first, down to the suspicious line, ready to hand to a human or an LLM
for validation.

No LLM runs here. Plain Python reads the code and builds short texts; **jev**, a classifier
that answers fixed questions with probabilities (~700 ms, about $42 per billion input tokens),
does all the judging.

On [PyGoat](https://github.com/adeyosemanputra/pygoat) (a deliberately vulnerable Django app,
~150 functions) a full run costs about **one cent**. Measured on 2026-10-02: $0.0106 for the
whole run; the top findings land on the planted SQL injection, `eval`, `pickle.loads` and
SSRF lines.

## How it works

A magnifying glass that goes down one level at a time. At each level jev rates every unit
and only the hot ones are opened at the next level, so the budget goes where the risk is.

```
repo
 │
 ▼  1. directory   jev reads names only         → drops tests, docs, migrations
 │
 ▼  2. file        jev reads imports + signatures → exposure: none / low / medium / high
 │
 ▼  3. function    jev reads the source          → unsafe input→sink / entry point / sink / sanitizer / neutral
 │
 ▼  4. line        jev picks one of the function's own lines → where the vulnerability happens
 │
 ▼
scan_result.json ──► viewer ──► "Copy to clipboard" ──► your agent validates (does not fix)
```

- **Heat** (0..1) = jev's probabilities weighted by the heat of each category, defined in
  `classification_levels.json`.
- **Budget**: each level gets a share; what a level does not spend rolls over to the next.
  Inside a level, units are processed hottest-parent first, so if money runs out, what is
  skipped is the coldest part.
- **Line level**: the answer options are the function's own lines, built at runtime. One call
  per suspicious function.

## Run

```bash
source ~/.secrets.sh                       # TYPESAFE_API_KEY
python viewer_server.py                    # http://localhost:7801/heatmap_viewer.html
```

In the viewer: choose a repo under `repos/`, a budget (max $0.05 per run, set in the JSON) and
press **Run analysis**. Or from the shell:

```bash
git clone --depth 1 https://github.com/adeyosemanputra/pygoat repos/pygoat
python attack_surface_scan.py repos/pygoat --budget 0.03
```

Each run writes `examples/<repo>/scan_result.json` (every node with heat, jev's answer and
tokens used) and `progress.log`.

## Files

| File | Role |
| --- | --- |
| `classification_levels.json` | questions, categories, heat weights, thresholds, budget shares, prices, agent instruction |
| `attack_surface_scan.py` | engine: extract units, build jev input, spend budget, write result |
| `viewer_server.py` | serves the viewer and starts runs |
| `heatmap_viewer.html` | file map + issue list + code with the suspected line |
| `examples/` | raw results per target codebase |
| `repos/` | cloned target codebases (git-ignored) |

## Extend

- **Change what is asked**: edit a level's question, categories or threshold in `classification_levels.json`.
- **Add a level** (classes, HTTP routes…): write `extract_<unit>(repo, parent_units)` in
  `attack_surface_scan.py`, register it in `UNIT_EXTRACTORS`, add a level with that `unit` to the JSON.
- **Calibrate cost**: each level in the result reports `measured_over_estimated_tokens`;
  adjust `estimate.chars_per_token` until it is close to 1.

## Limits

- Python only (uses the standard `ast` module).
- Each function is judged alone: a vulnerability split across two functions can be missed.
- Heat is a ranking for review, not a verdict.
