#!/usr/bin/env python3
"""
Claude Code Secret Guard
========================
A blocking hook that scans prompts and tool invocations for sensitive data
or dangerous operations. Runs locally, never uploads anything.

Layers:
  1. Regex patterns for known secret formats (AWS, GitHub, Stripe, JWT, etc.)
  2. Path-based blocks for sensitive files (.env, id_rsa, ~/.aws, etc.)
  3. Dangerous shell command detection (curl|sh, rm -rf /, etc.)
  4. Optional semantic LLM check via Claude Haiku (set SECRET_GUARD_LLM=1)

Override: prefix any prompt with [GUARD-OK] to bypass for that prompt only.

Exit codes:
  0  allow
  2  block (Claude Code shows stderr to user and Claude)
"""

import json
import os
import re
import sys
from pathlib import Path

OVERRIDE_TOKEN = "[GUARD-OK]"

SECRET_PATTERNS = {
    "AWS Access Key":        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "AWS Secret Key":        re.compile(r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    "GitHub Classic Token":  re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    "GitHub Fine PAT":       re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    "Anthropic API Key":     re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}"),
    "OpenAI API Key":        re.compile(r"\bsk-(?!ant-)[A-Za-z0-9]{20,}"),
    "Stripe Live Key":       re.compile(r"\b(sk|pk|rk)_live_[A-Za-z0-9]{24,}\b"),
    "Slack Token":           re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "Google API Key":        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Google OAuth":          re.compile(r"ya29\.[0-9A-Za-z\-_]+"),
    "Private Key Block":     re.compile(r"-----BEGIN (?:(?:RSA|OPENSSH|EC|DSA|PGP) )?PRIVATE KEY(?: BLOCK)?-----"),
    "JWT":                   re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "Generic Secret Assign": re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"),
    "Bearer Header":         re.compile(r"(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._\-]{20,}"),
    "Heroku API Key":        re.compile(r"\b[hH]eroku.{0,20}['\"][0-9a-fA-F]{32}['\"]"),
}

SENSITIVE_PATH_PATTERNS = [
    re.compile(r"(^|/)\.env(\.|$)"),
    re.compile(r"(^|/)\.envrc$"),
    re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$"),
    re.compile(r"\.pem$"),
    re.compile(r"\.key$"),
    re.compile(r"\.p12$"),
    re.compile(r"\.pfx$"),
    re.compile(r"\.aws/credentials"),
    re.compile(r"\.aws/config"),
    re.compile(r"(^|/)\.ssh/(?!known_hosts$|config$)"),
    re.compile(r"(^|/)credentials\.json$"),
    re.compile(r"service[-_]account.*\.json$"),
    re.compile(r"(^|/)\.netrc$"),
    re.compile(r"(^|/)\.pgpass$"),
    re.compile(r"\.config/gh/"),
    re.compile(r"google[-_]credentials"),
    re.compile(r"firebase[-_]adminsdk.*\.json$"),
    re.compile(r"(^|/)secrets?\.(yml|yaml|json|toml)$"),
]

DANGEROUS_BASH_PATTERNS = [
    (re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|fish)\b"), "pipe-to-shell"),
    (re.compile(r"\brm\s+-rf?\s+(/|~|\$HOME|\*)(\s|$)"),                     "rm -rf on home/root"),
    (re.compile(r":\(\)\s*\{[^}]*:\s*\|\s*:\s*&[^}]*\}\s*;\s*:"),            "fork bomb"),
    (re.compile(r"\bchmod\s+-R\s+0*777\b"),                                  "chmod 777 recursive"),
    (re.compile(r"\bdd\s+[^|;&]*of=/dev/(sd|hd|nvme|disk)"),                 "dd to raw disk"),
    (re.compile(r">\s*/dev/(sd|hd|nvme|disk)"),                              "redirect to raw disk"),
    (re.compile(r"\bmkfs\."),                                                "filesystem format"),
    (re.compile(r"\bgit\s+push\s+.*--force(-with-lease)?\s+.*\b(main|master|production)\b"), "force push to protected branch"),
    (re.compile(r"\bgit\s+push\s+.*\s+\+"),                                  "git push with force-refspec"),
    (re.compile(r"\bhistory\s+-c\b"),                                        "shell history wipe"),
    (re.compile(r"\bshred\s+"),                                              "shred"),
]

def find_secrets(text):
    findings = []
    for name, pat in SECRET_PATTERNS.items():
        for m in pat.finditer(text):
            sample = m.group(0)
            preview = sample[:8] + "…" + sample[-4:] if len(sample) > 16 else sample[:6] + "…"
            findings.append((name, preview))
    return findings

def find_sensitive_path(s):
    for pat in SENSITIVE_PATH_PATTERNS:
        if pat.search(s):
            return pat.pattern
    return None

def find_dangerous_command(cmd):
    for pat, label in DANGEROUS_BASH_PATTERNS:
        if pat.search(cmd):
            return label
    return None

def llm_check(text, kind):
    """Optional Haiku-based semantic check. Returns dict or None."""
    if os.environ.get("SECRET_GUARD_LLM") != "1":
        return None
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
    except ImportError:
        return None
    if len(text) < 40:
        return None

    client = anthropic.Anthropic(api_key=api_key)
    try:
        msg = client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=150,
            messages=[{
                "role": "user",
                "content": (
                    "You are a strict security guard. The user is about to send the "
                    "following content to a third-party AI service (Anthropic Claude). "
                    "Decide if it contains material that should NOT leave the user's machine.\n\n"
                    "BLOCK if you see: live credentials, real passwords, private keys, "
                    "PII of identifiable third parties (full names + contact info, SSN, "
                    "medical, financial), confidential business data, NDA-covered content.\n"
                    "ALLOW: code, generic questions, public information, the user's own "
                    "non-sensitive personal info, fictional examples, syntax like FOO=xxx.\n\n"
                    f"Kind: {kind}\n"
                    f"Content (first 3000 chars):\n```\n{text[:3000]}\n```\n\n"
                    "Reply ONLY with compact JSON: "
                    '{"block": true|false, "reason": "<one short sentence>"}'
                )
            }],
        )
        raw = msg.content[0].text.strip()
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            return None
        return json.loads(m.group(0))
    except Exception:
        return None

def block(*lines):
    print("⛔ Secret Guard blocked this action.", file=sys.stderr)
    for ln in lines:
        print(f"   {ln}", file=sys.stderr)
    print("", file=sys.stderr)
    print(f"   Override: prefix prompt with {OVERRIDE_TOKEN} to bypass once.", file=sys.stderr)
    sys.exit(2)

def handle_user_prompt_submit(data):
    prompt = data.get("prompt", "") or ""
    if OVERRIDE_TOKEN in prompt:
        sys.exit(0)

    findings = find_secrets(prompt)
    if findings:
        lines = ["Detected potential secrets in your prompt:"]
        for name, preview in findings[:5]:
            lines.append(f"• {name}: {preview}")
        block(*lines)

    verdict = llm_check(prompt, "user prompt")
    if verdict and verdict.get("block"):
        block(f"LLM check: {verdict.get('reason', 'sensitive content')}")

    sys.exit(0)

def handle_pre_tool_use(data):
    tool = data.get("tool_name", "")
    inp = data.get("tool_input", {}) or {}

    if tool in ("Read", "Edit", "Write", "NotebookEdit"):
        path = inp.get("file_path") or inp.get("notebook_path") or ""
        match = find_sensitive_path(path)
        if match:
            block(
                f"{tool} targets sensitive path: {path}",
                f"Pattern matched: {match}",
            )

    elif tool == "Bash":
        cmd = inp.get("command", "") or ""

        danger = find_dangerous_command(cmd)
        if danger:
            block(
                f"Dangerous shell command: {danger}",
                f"Command: {cmd[:160]}",
            )

        for pat in SENSITIVE_PATH_PATTERNS:
            if pat.search(cmd):
                block(
                    f"Bash command references sensitive path",
                    f"Matched: {pat.pattern}",
                    f"Command: {cmd[:160]}",
                )

        leaked = find_secrets(cmd)
        if leaked:
            lines = ["Bash command appears to contain a secret literal:"]
            for name, preview in leaked[:5]:
                lines.append(f"• {name}: {preview}")
            block(*lines)

    elif tool in ("WebFetch", "WebSearch"):
        url_or_query = inp.get("url") or inp.get("query") or ""
        leaked = find_secrets(url_or_query)
        if leaked:
            lines = [f"{tool} input contains a secret literal:"]
            for name, preview in leaked[:5]:
                lines.append(f"• {name}: {preview}")
            block(*lines)

    sys.exit(0)

def main():
    event = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    if event == "UserPromptSubmit":
        handle_user_prompt_submit(data)
    elif event == "PreToolUse":
        handle_pre_tool_use(data)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
