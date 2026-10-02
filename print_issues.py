"""Print the issues of a scan_result.json as the same compact text the viewer copies.

Usage:
    python print_issues.py examples/pygoat/scan_result.json
    python print_issues.py examples/pygoat/scan_result.json --file introduction/views.py --top 10
"""
import argparse
import json
from pathlib import Path

HERE = Path(__file__).parent


def top_category(function_node):
    return max(function_node["answer"], key=function_node["answer"].get).replace("_", " ")


def suspected_line(result, function_node):
    for node in result["nodes"]:
        if node["level"] == "line" and node["path"] == function_node["path"] and node["line"] == function_node["line"]:
            return max(node["answer"], key=lambda line: line["probability"])
    return None


def issues_text(result, file=None, top=None):
    functions = [n for n in result["nodes"] if n["level"] == "function" and n["passed"]]
    if file:
        functions = [n for n in functions if n["path"] == file]
    functions = sorted(functions, key=lambda n: -n["heat"])[:top]
    instructions = json.loads((HERE / "classification_levels.json").read_text())["agent_instructions"]
    lines = [instructions, f"Repo: {result['repo']}", ""]
    for i, f in enumerate(functions, 1):
        line = suspected_line(result, f)
        lines.append(f"{i}. {f['path']}:{line['line'] if line else f['line']} {f['name']}() "
                     f"[{top_category(f)}, heat {f['heat']:.2f}]" + (f"\n   {line['code']}" if line else ""))
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_result")
    parser.add_argument("--file", help="only issues in this file (path as shown in the result)")
    parser.add_argument("--top", type=int, help="only the N hottest issues")
    args = parser.parse_args()
    print(issues_text(json.loads(Path(args.scan_result).read_text()), args.file, args.top))
