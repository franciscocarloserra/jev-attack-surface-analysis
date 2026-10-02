# JEV Attack Surface Analysis

![JEV Attack Surface Analysis on PyGoat](docs/screenshot.png)

**Browse the examples:** https://franciscocarloserra.github.io/jev-attack-surface-analysis/ (PyGoat and NodeGoat runs, read-only)

Point it at a backend repo (Python, JavaScript or TypeScript) and a budget in dollars. You get a ranked list of the places an
attacker would look first, down to the suspicious line, ready to hand to a human or an LLM
for validation.

No LLM runs here. Plain Python reads the code and builds short texts; **jev**, a classifier
that answers fixed questions with probabilities (~700 ms, about $42 per billion input tokens),
does all the judging.

On [PyGoat](https://github.com/adeyosemanputra/pygoat) (a deliberately vulnerable Django app,
~150 functions) a full run costs about **one cent**. Measured on 2026-10-02: $0.0106 for the
whole run; the top findings land on the planted SQL injection, `eval`, `pickle.loads` and
SSRF lines.

**Tested so far** only against two deliberately vulnerable apps:
[PyGoat](https://github.com/adeyosemanputra/pygoat) (Python/Django) and
[NodeGoat](https://github.com/OWASP/NodeGoat) (JavaScript/Express).

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
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
source ~/.secrets.sh                       # TYPESAFE_API_KEY
python3 viewer_server.py                    # http://localhost:7801/heatmap_viewer.html
```

In the viewer: choose a repo under `repos/` (and a saved run of it), a budget (max $0.05 per run, set in the JSON) and
press **Run analysis**. Or from the shell:

```bash
git clone --depth 1 https://github.com/adeyosemanputra/pygoat repos/pygoat
git clone --depth 1 https://github.com/OWASP/NodeGoat repos/nodegoat
.venv/bin/python attack_surface_scan.py repos/pygoat --budget 0.03
```

Each run writes `examples/<repo>/scan_result.json` (latest) and keeps a copy in
`examples/<repo>/runs/<run id>.json`. Every result carries `run`: id, timestamp, scanner
version (`git describe`) and a hash of `classification_levels.json`, so runs can be compared.

## Files

| File | Role |
| --- | --- |
| `classification_levels.json` | languages (parsing rules), questions, categories, heat weights, thresholds, budget shares, prices, agent instruction |
| `attack_surface_scan.py` | engine: extract units, build jev input, spend budget, write result |
| `viewer_server.py` | serves the viewer and starts runs |
| `print_issues.py` | prints the issue list for an agent (same text as the copy button) |
| `AGENTS.md` | how an agent runs the scan and parses the result |
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

- Python, JavaScript and TypeScript (tree-sitter). Another language = one entry in `languages`
  in `classification_levels.json` naming its import, function and class node types.
- Each function is judged alone: a vulnerability split across two functions can be missed.
- Heat is a ranking for review, not a verdict.
