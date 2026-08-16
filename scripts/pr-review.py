#!/usr/bin/env python3
"""Run an owner-triggered PR review from a trusted GitHub Actions checkout."""

import json
import os
import sys

import requests

MAX_DIFF_CHARS = 100_000
DEFAULT_MODEL_FAST = "gpt-5.6-luna"
DEFAULT_MODEL_DEEP = "gpt-5.6-terra"
DEFAULT_MAX_COMPLETION_TOKENS = 8192
# max_completion_tokens is shared by reasoning and visible output. At xhigh
# effort, 25000 was consumed by reasoning alone and produced an empty review.
DEEP_MAX_COMPLETION_TOKENS = 64000
DEFAULT_LLM_TIMEOUT_SECONDS = 120
DEEP_LLM_TIMEOUT_SECONDS = 300
FAST_REASONING_EFFORT = "low"
DEEP_REASONING_EFFORT = "xhigh"


class LLMReviewError(RuntimeError):
    """The provider returned a response that cannot be safely published as review."""


SYSTEM_PROMPT = """Review this pull request for Agent Evidence Level, a vendor-neutral public
standard plus a Go reference checker and generator-owned fixture corpus.

Focus on material errors in the evidence model, normative claims, artifact schemas, checker
correctness, fixture reproducibility, and compatibility. In particular, flag changes that could
let an artifact earn a grade it cannot prove, turn FAIL or UNABLE-TO-VERIFY into PASS, make a
fixture hand-edited instead of generator-owned, or introduce vendor-specific claims.

Do not report style nits. For every finding give severity, file and relevant symbol or section,
why it matters, and a concrete correction. If there are no material issues, say exactly:
No material issues found in this diff."""


def get_pr_diff(repo: str, pr_number: str, token: str) -> str:
    response = requests.get(
        f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3.diff"},
        timeout=30,
    )
    response.raise_for_status()
    return response.text


def truncate_diff(diff: str) -> str:
    if len(diff) <= MAX_DIFF_CHARS:
        return diff
    return diff[:MAX_DIFF_CHARS] + f"\n\n... diff truncated at {MAX_DIFF_CHARS} of {len(diff)} chars"


def model_for_mode(mode: str) -> str:
    if mode == "deep":
        return os.environ.get("PR_REVIEW_MODEL_DEEP") or DEFAULT_MODEL_DEEP
    return os.environ.get("PR_REVIEW_MODEL_FAST") or DEFAULT_MODEL_FAST


def build_llm_payload(model: str, diff: str, mode: str) -> dict:
    deep = mode == "deep"
    return {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Review this pull request diff:\n\n```diff\n{diff}\n```"},
        ],
        "max_completion_tokens": DEEP_MAX_COMPLETION_TOKENS if deep else DEFAULT_MAX_COMPLETION_TOKENS,
        "reasoning_effort": DEEP_REASONING_EFFORT if deep else FAST_REASONING_EFFORT,
    }


def summarize_usage(data: dict) -> str:
    usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
    details = usage.get("completion_tokens_details")
    reasoning = details.get("reasoning_tokens", "unknown") if isinstance(details, dict) else "unknown"
    return f"prompt={usage.get('prompt_tokens', 'unknown')}, completion={usage.get('completion_tokens', 'unknown')}, reasoning={reasoning}"


def extract_chat_content(data: dict) -> str:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise LLMReviewError("LLM returned no choices.")
    choice = choices[0] if isinstance(choices[0], dict) else {}
    message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
    content = message.get("content", "")
    if isinstance(content, list):
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    if not isinstance(content, str) or not content.strip():
        raise LLMReviewError(f"LLM returned empty content (finish_reason={choice.get('finish_reason', 'unknown')}; {summarize_usage(data)}).")
    if choice.get("finish_reason") == "length":
        content += f"\n\n> **Warning:** This review was truncated ({summarize_usage(data)}). Treat it as incomplete."
    return content


def call_llm(diff: str, mode: str) -> str:
    litellm_url = os.environ.get("LITELLM_BASE_URL", "")
    litellm_key = os.environ.get("LITELLM_API_KEY", "")
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if litellm_url and litellm_key:
        api_url = litellm_url.rstrip("/") + "/chat/completions"
        api_key = litellm_key
    elif api_key:
        api_url = "https://api.openai.com/v1/chat/completions"
    else:
        raise LLMReviewError(
            "No LLM API configured. Set LITELLM_BASE_URL + LITELLM_API_KEY "
            "or OPENAI_API_KEY in repository secrets."
        )
    model = model_for_mode(mode)
    response = requests.post(
        api_url,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=build_llm_payload(model, diff, mode),
        timeout=DEEP_LLM_TIMEOUT_SECONDS if mode == "deep" else DEFAULT_LLM_TIMEOUT_SECONDS,
    )
    if response.status_code != 200:
        raise LLMReviewError(
            f"LLM API returned {response.status_code} for model `{model}`."
        )
    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError) as error:
        raise LLMReviewError("LLM returned invalid JSON.") from error
    if not isinstance(data, dict):
        raise LLMReviewError("LLM returned a non-object JSON response.")
    return extract_chat_content(data)


def post_comment(repo: str, pr_number: str, token: str, body: str) -> None:
    response = requests.post(
        f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"},
        json={"body": body},
        timeout=30,
    )
    response.raise_for_status()


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("REPO", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    mode = os.environ.get("REVIEW_MODE", "default")
    if not token or not repo or not pr_number:
        raise SystemExit("Missing GITHUB_TOKEN, REPO, or PR_NUMBER.")
    try:
        diff = get_pr_diff(repo, pr_number, token)
        if not diff.strip():
            post_comment(repo, pr_number, token, "## AI Review\n\nNo diff found for this PR.")
            return
        review = call_llm(truncate_diff(diff), mode)
        command = "/review deep" if mode == "deep" else "/review"
        post_comment(repo, pr_number, token, f"## AI Review (`{command}`)\n\n**Model:** `{model_for_mode(mode)}`\n\n---\n\n{review}")
    except (requests.RequestException, LLMReviewError) as error:
        post_comment(repo, pr_number, token, f"## AI Review Error\n\n{error}")
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
