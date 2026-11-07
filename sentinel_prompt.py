"""Sentinel Guardian: deterministic, explainable Python source checks.

This is a small static-analysis prototype, not a complete security scanner.
It reports selected risky constructs; it does not execute or patch submitted code.
"""
from __future__ import annotations
import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

CREDENTIAL_NAMES = re.compile(r"(password|passwd|secret|api[_-]?key|access[_-]?token)", re.I)
PLACEHOLDERS = {"", "changeme", "change-me", "example", "placeholder", "your-token", "your_api_key", "none", "null", "xxx", "redacted"}

class SentinelVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[dict[str, Any]] = []

    def add(self, node: ast.AST, rule_id: str, severity: str, message: str) -> None:
        self.findings.append({"rule_id": rule_id, "severity": severity, "line": getattr(node, "lineno", None), "message": message})

    @staticmethod
    def call_name(node: ast.expr) -> tuple[str | None, str]:
        if isinstance(node, ast.Name):
            return None, node.id
        if isinstance(node, ast.Attribute):
            module, _ = SentinelVisitor.call_name(node.value)
            return module, node.attr
        return None, ""

    def visit_Call(self, node: ast.Call) -> None:
        module, name = self.call_name(node.func)
        if name in {"eval", "exec"} and module is None:
            self.add(node, "PY001", "HIGH", f"Dynamic code execution via {name}()")
        if name in {"run", "Popen", "call", "check_call", "check_output"} and module == "subprocess":
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                self.add(node, "PY002", "HIGH", "Subprocess invoked with shell=True")
        if module == "pickle" and name in {"load", "loads"}:
            self.add(node, "PY003", "HIGH", f"Deserialization through pickle.{name}() can execute attacker-controlled payloads")
        if module == "yaml" and name == "load":
            safe = any(k.arg == "Loader" and isinstance(k.value, ast.Attribute) and k.value.attr in {"SafeLoader", "CSafeLoader"} for k in node.keywords)
            if not safe:
                self.add(node, "PY004", "MEDIUM", "yaml.load() without an explicit safe loader")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            for name in self.target_names(target):
                self.check_credential_literal(name, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            for name in self.target_names(node.target):
                self.check_credential_literal(name, node.value, node)
        self.generic_visit(node)

    @staticmethod
    def target_names(target: ast.expr) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            return [name for element in target.elts for name in SentinelVisitor.target_names(element)]
        return []

    def check_credential_literal(self, name: str, value: ast.expr, node: ast.AST) -> None:
        if not CREDENTIAL_NAMES.search(name) or not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        candidate = value.value.strip()
        if len(candidate) >= 8 and candidate.lower() not in PLACEHOLDERS:
            self.add(node, "PY005", "HIGH", f"Possible hard-coded credential assigned to {name}")

def analyze_code(code_snippet: str) -> str:
    """Return a stable JSON report for the supported Python checks."""
    try:
        tree = ast.parse(code_snippet)
    except SyntaxError as error:
        report = {"scanner": "Sentinel Guardian", "scanner_version": "0.2.0", "status": "parse_error", "findings": [], "error": {"line": error.lineno, "message": error.msg}, "limitations": ["Only Python syntax is analyzed.", "This prototype is not a complete security scanner."]}
        return json.dumps(report, sort_keys=True)
    visitor = SentinelVisitor()
    visitor.visit(tree)
    findings = sorted(visitor.findings, key=lambda item: (item["line"] or 0, item["rule_id"]))
    report = {
        "scanner": "Sentinel Guardian", "scanner_version": "0.2.0",
        "status": "findings" if findings else "no_findings", "findings": findings,
        "summary": {"total": len(findings), "high": sum(x["severity"] == "HIGH" for x in findings), "medium": sum(x["severity"] == "MEDIUM" for x in findings)},
        "limitations": ["Only selected Python AST patterns are checked; absence of findings is not proof of safety.", "No data-flow analysis, dependency analysis, runtime monitoring, or automatic remediation is performed.", "Credential detection is heuristic and may produce false positives or miss secrets."]
    }
    return json.dumps(report, sort_keys=True)

def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {Path(sys.argv[0]).name} <python-file>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    try:
        report = json.loads(analyze_code(path.read_text(encoding="utf-8")))
    except OSError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 1 if report["status"] == "findings" else 0

if __name__ == "__main__":
    raise SystemExit(main())
