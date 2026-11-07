# Sentinel Guardian 🛡️

**EmergentSoft · Security & Integrity Layer**

## Status

**Prototype / security architecture.**

Sentinel Guardian is a security and integrity component associated with EmergentSoft's AI orchestration stack. The repository contains prototype implementation and demonstration material; it should not be interpreted as evidence of a production security service or security certification.

## Purpose

Enterprise AI systems require a controlled security boundary before autonomous actions can affect business infrastructure. Sentinel is intended to provide integrity controls around governed orchestration.

## Current scope

- QAIzero-oriented orchestration integration patterns
- Tamper-detection concepts
- Runtime-integrity monitoring concepts
- Lightweight security-control prototypes

## Architecture position

`Enterprise Infrastructure → M8s → Digital Mates → QAIzero → Sentinel → Controlled Execution`

Sentinel is a security component, not a substitute for M8s governance or the specialized Mates.

## Evidence boundary

The implementation in this repository is the source of truth for current capabilities. Do not infer production deployment, cryptographic guarantees, security certification, blockchain anchoring or external validation from architectural descriptions alone.

## Commercial role

Sentinel is positioned as an enterprise security component for future governed AI deployments.

## Security & IP

See `SECURITY.md` and `LICENSE`.

## Owner

Alejandro Lamas — Founder & CEO, EmergentSoft


## Implemented Python static-analysis prototype

The current branch includes a deterministic AST-based analyzer in `sentinel_prompt.py` with unit tests and a GitHub Actions workflow. The prototype checks a limited set of patterns:

| Rule | Check | Severity |
|---|---|---|
| PY001 | `eval()` / `exec()` dynamic execution | HIGH |
| PY002 | `subprocess` with `shell=True` | HIGH |
| PY003 | `pickle.load()` / `pickle.loads()` | HIGH |
| PY004 | `yaml.load()` without an explicit safe loader | MEDIUM |
| PY005 | Possible hard-coded credential string assignments | HIGH |

Run locally:

```bash
python sentinel_prompt.py path/to/source.py
python -m unittest discover -s tests -v
```

The analyzer emits structured JSON findings with rule IDs and source line numbers. It does not execute analyzed code, automatically patch files, perform data-flow analysis, inspect dependencies, or monitor runtime behavior. A clean report is not proof that a program is secure. Credential detection is heuristic and may produce false positives or miss secrets.

The TypeScript sidecar and mapping files remain illustrative scaffolding; their log messages are not evidence of blockchain transactions or deployed The Graph indexing.
