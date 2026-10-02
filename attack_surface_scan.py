"""Attack surface heatmap of a Python codebase, classified top-down by jev.

Usage:
    python attack_surface_scan.py <repo_path> --budget 0.05

Levels, questions and thresholds live in classification_levels.json.
This file only walks the repo, builds the text sent to jev, spends the budget
hottest-first and writes scan_result.json after every batch.
"""
import argparse
import ast
import json
import os
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

JEV_URL = "https://api.typesafe.ai/v1/systemone"
JEV_MODEL = "jev-latest"
HERE = Path(__file__).parent


# ---------- unit extractors: repo -> list of units (one per thing jev classifies) ----------

def extract_directories(repo, parent_units):
    """Every directory that directly contains .py files."""
    units = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        py_files = sorted(f for f in filenames if f.endswith(".py"))
        if not py_files:
            continue
        rel = os.path.relpath(dirpath, repo)
        state = f"directory: {rel}\nsubdirectories: {', '.join(dirnames) or '-'}\npython files: {', '.join(py_files)}"
        size = sum(len((Path(dirpath) / f).read_text(errors="replace").splitlines()) for f in py_files)
        units.append({"path": rel, "name": rel, "line": None, "parent_heat": 1.0, "state": state, "size": size})
    return units


def extract_files(repo, parent_units):
    """Every .py file inside a directory that passed the previous level: imports + signatures."""
    units = []
    for parent in parent_units:
        directory = Path(repo) / parent["path"]
        for file in sorted(directory.glob("*.py")):
            rel = str(file.relative_to(repo))
            tree = parse_python(file)
            if tree is None:
                continue
            state = f"file: {rel}\nimports: {', '.join(list_imports(tree)) or '-'}\ndefinitions:\n" + "\n".join(list_signatures(tree))
            size = len(file.read_text(errors="replace").splitlines())
            units.append({"path": rel, "name": rel, "line": None, "parent_heat": parent["heat"], "state": state, "size": size})
    return units


def extract_functions(repo, parent_units):
    """Every function and method inside a file that passed the previous level: full source."""
    units = []
    for parent in parent_units:
        file = Path(repo) / parent["path"]
        source = file.read_text(errors="replace")
        tree = parse_python(file)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = ast.get_source_segment(source, node) or ""
                state = f"file: {parent['path']}\nimports: {', '.join(list_imports(tree))}\n\n{body}"
                units.append({"path": parent["path"], "name": node.name, "line": node.lineno,
                              "parent_heat": parent["heat"], "state": state, "source": body, "size": len(body.splitlines())})
    return units


def extract_lines(repo, parent_units):
    """One unit per hot function: jev picks which of its lines is the vulnerable one.
    The answer options are the function's own lines, built here at runtime."""
    units = []
    for parent in parent_units:
        criteria = {}
        for offset, text in enumerate(parent["source"].splitlines()):
            code = text.strip()
            if code and not code.startswith("#"):
                criteria[f"line {parent['line'] + offset}"] = code[:200]
        units.append({"path": parent["path"], "name": parent["name"], "line": parent["line"],
                      "parent_heat": parent["heat"], "state": parent["state"], "criteria": criteria})
    return units


UNIT_EXTRACTORS = {
    "directory": extract_directories,
    "file": extract_files,
    "function": extract_functions,
    "line": extract_lines,
}


def parse_python(file):
    try:
        return ast.parse(Path(file).read_text(errors="replace"))
    except SyntaxError:
        return None


def list_imports(tree):
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names += [f"{node.module}.{a.name}" for a in node.names]
    return names


def list_signatures(tree):
    lines = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            decorators = "".join(f"@{ast.unparse(d)} " for d in node.decorator_list)
            args = f"({ast.unparse(node.args)})" if not isinstance(node, ast.ClassDef) else ""
            kind = "class" if isinstance(node, ast.ClassDef) else "def"
            lines.append(f"{decorators}{kind} {node.name}{args}")
    return lines


# ---------- jev ----------

def build_jev_question(question):
    """Our question format -> jev's (criteria with descriptions instead of heat weights)."""
    jev_question = {"type": question["type"], "instructions": question["instructions"]}
    if question.get("criteria_from_unit"):
        return jev_question
    if question["type"] == "choice":
        jev_question["criteria"] = {k: v["description"] for k, v in question["criteria"].items()}
    if question["type"] == "score":
        jev_question["criteria"] = [f"{k}: {v['description']}" for k, v in question["criteria"].items()]
    return jev_question


def ask_jev(state, question, runtime_criteria=None):
    jev_question = build_jev_question(question)
    if runtime_criteria:
        jev_question["criteria"] = runtime_criteria
    body = {"state": state, "model": JEV_MODEL, "questions": {"q": jev_question}}
    request = urllib.request.Request(JEV_URL, data=json.dumps(body).encode(), headers={
        "Authorization": f"Bearer {os.environ['TYPESAFE_API_KEY']}", "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def heat_from_answer(answer, question, unit):
    """Turn jev's distribution into one number 0..1 using the heat weights in the levels file.
    Levels with runtime criteria (lines) only locate, so they keep the parent's heat."""
    if question.get("criteria_from_unit"):
        return unit["parent_heat"]
    if question["type"] == "noul":
        return answer["noul"]
    weights = [v["heat"] for v in question["criteria"].values()]
    names = list(question["criteria"])
    probabilities = answer["probabilities"]
    if question["type"] == "score":  # score answers are keyed by index: "0", "1", ...
        return sum(probabilities[str(i)] * w for i, w in enumerate(weights))
    return sum(probabilities[n] * w for n, w in zip(names, weights))


def readable_answer(answer, question, unit):
    if question.get("criteria_from_unit"):  # every line with its probability, in source order
        return [{"line": int(k.split()[1]), "code": v, "probability": round(answer["probabilities"][k], 3)}
                for k, v in unit["criteria"].items()]
    if question["type"] == "noul":
        return {"yes": round(answer["noul"], 3)}
    names = list(question["criteria"])
    if question["type"] == "score":
        return {names[int(i)]: round(p, 3) for i, p in answer["probabilities"].items()}
    return {n: round(answer["probabilities"][n], 3) for n in names}


# ---------- budget ----------

def estimate_tokens(state, config):
    return len(state) / config["estimate"]["chars_per_token"] + config["estimate"]["question_overhead_tokens"]


def cost_usd(usage, config):
    pricing = config["pricing"]
    return usage["input_tokens"] * pricing["usd_per_input_token"] + usage["output_tokens"] * pricing["usd_per_output_token"]


# ---------- main loop ----------

def scan(repo, budget_usd, config, out_path):
    result = {"repo": str(repo), "budget_usd": budget_usd, "spent_usd": 0.0, "levels": [], "nodes": []}
    usd_per_token = config["pricing"]["usd_per_input_token"]
    log = open(out_path.parent / "progress.log", "w")
    passed_units = []
    unspent_from_previous_levels = 0.0

    for level in config["levels"]:
        level_budget = budget_usd * level["budget_share"] + unspent_from_previous_levels
        level_spent = 0.0
        units = UNIT_EXTRACTORS[level["unit"]](repo, passed_units)
        units.sort(key=lambda u: -u["parent_heat"])  # hottest parents first
        classified = []

        for start in range(0, len(units), config["parallel_requests"]):
            batch = units[start:start + config["parallel_requests"]]
            for unit in batch:
                unit["state"] = unit["state"][:config["max_state_chars"]]
            batch_estimate = sum(estimate_tokens(u["state"], config) for u in batch) * usd_per_token
            if level_spent + batch_estimate > level_budget:
                break
            with ThreadPoolExecutor(len(batch)) as pool:
                responses = list(pool.map(lambda u: ask_jev(u["state"], level["question"], u.get("criteria")), batch))
            for unit, response in zip(batch, responses):
                answer = response["answers"]["q"]
                unit_cost = cost_usd(response["usage"], config)
                level_spent += unit_cost
                unit["heat"] = round(heat_from_answer(answer, level["question"], unit), 3)
                unit["passed"] = unit["heat"] >= level["pass_heat"]
                node = {"level": level["name"], "path": unit["path"], "name": unit["name"], "line": unit["line"], "size": unit.get("size"),
                        "heat": unit["heat"], "passed": unit["passed"], "answer": readable_answer(answer, level["question"], unit),
                        "tokens": response["usage"]["input_tokens"], "estimated_tokens": round(estimate_tokens(unit["state"], config))}
                result["nodes"].append(node)
                classified.append(unit)
            result["spent_usd"] = round(sum(l["spent_usd"] for l in result["levels"]) + level_spent, 6)
            out_path.write_text(json.dumps(result, indent=1))
            print(f"{level['name']}: {len(classified)}/{len(units)} spent ${level_spent:.5f} of ${level_budget:.5f}", file=log, flush=True)

        passed_units = [u for u in classified if u["passed"]]
        measured = sum(n["tokens"] for n in result["nodes"] if n["level"] == level["name"])
        estimated = sum(n["estimated_tokens"] for n in result["nodes"] if n["level"] == level["name"])
        result["levels"].append({"name": level["name"], "units_found": len(units), "units_classified": len(classified),
                                 "units_passed": len(passed_units), "spent_usd": round(level_spent, 6),
                                 "budget_usd": round(level_budget, 6),
                                 "measured_over_estimated_tokens": round(measured / estimated, 3) if estimated else None})
        unspent_from_previous_levels = level_budget - level_spent
        out_path.write_text(json.dumps(result, indent=1))
        print(json.dumps(result["levels"][-1]))

    print(f"spent ${result['spent_usd']:.5f} of ${budget_usd} -> {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("repo")
    parser.add_argument("--budget", type=float, required=True, help="max USD for this run")
    parser.add_argument("--levels", default=HERE / "classification_levels.json")
    parser.add_argument("--out", help="default: examples/<repo name>/scan_result.json")
    args = parser.parse_args()
    out = Path(args.out or HERE / "examples" / Path(args.repo).resolve().name / "scan_result.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    scan(Path(args.repo), args.budget, json.loads(Path(args.levels).read_text()), out)
