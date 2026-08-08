#!/usr/bin/env python3
"""Focused tests for PR review routing and failure handling."""

import importlib.util
import pathlib
import unittest
from unittest import mock


SCRIPT_PATH = pathlib.Path(__file__).with_name("pr-review.py")
WORKFLOW_PATH = SCRIPT_PATH.parents[1] / ".github" / "workflows" / "pr-review.yaml"
SPEC = importlib.util.spec_from_file_location("pr_review", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load {SCRIPT_PATH}")
pr_review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pr_review)


class FakeResponse:
    def __init__(self, data=None, status_code=200, text=""):
        self.data = data if data is not None else {}
        self.status_code = status_code
        self.text = text

    def json(self):
        return self.data


class InvalidJSONResponse(FakeResponse):
    def json(self):
        raise ValueError("invalid JSON")


class RoutingTests(unittest.TestCase):
    def test_defaults_route_review_and_deep_to_gpt56_tiers(self):
        with mock.patch.dict(pr_review.os.environ, {}, clear=True):
            self.assertEqual(pr_review.model_for_mode("default"), "gpt-5.6-luna")
            self.assertEqual(pr_review.model_for_mode("deep"), "gpt-5.6-terra")
        normal = pr_review.build_llm_payload("gpt-5.6-luna", "diff", "default")
        deep = pr_review.build_llm_payload("gpt-5.6-terra", "diff", "deep")
        self.assertNotIn("temperature", normal)
        self.assertEqual(normal["reasoning_effort"], "low")
        self.assertEqual(normal["max_completion_tokens"], 8192)
        self.assertEqual(deep["reasoning_effort"], "xhigh")
        self.assertEqual(deep["max_completion_tokens"], 64000)

    def test_workflow_uses_owner_gate_trusted_checkout_and_runner_defaults(self):
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("github.event.comment.user.login == 'luckyPipewrench'", workflow)
        self.assertIn("github.event.comment.author_association == 'OWNER'", workflow)
        self.assertIn("github.event.issue.pull_request", workflow)
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("timeout-minutes: 10", workflow)
        self.assertIn("LITELLM_BASE_URL: ${{ secrets.LITELLM_BASE_URL }}", workflow)
        self.assertIn("LITELLM_API_KEY: ${{ secrets.LITELLM_API_KEY }}", workflow)
        self.assertIn("group: pr-review-${{ github.repository }}-${{ github.event.issue.number }}", workflow)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn("python -m unittest scripts/pr_review_test.py", workflow)
        self.assertIn("PR_REVIEW_MODEL_FAST: ${{ vars.PR_REVIEW_MODEL_FAST }}", workflow)
        self.assertIn("PR_REVIEW_MODEL_DEEP: ${{ vars.PR_REVIEW_MODEL_DEEP }}", workflow)
        self.assertNotRegex(workflow, r"PR_REVIEW_MODEL_(?:FAST|DEEP): gpt-")

    def test_empty_overrides_use_reviewed_defaults(self):
        with mock.patch.dict(pr_review.os.environ, {"PR_REVIEW_MODEL_FAST": "", "PR_REVIEW_MODEL_DEEP": ""}, clear=True):
            self.assertEqual(pr_review.model_for_mode("default"), pr_review.DEFAULT_MODEL_FAST)
            self.assertEqual(pr_review.model_for_mode("deep"), pr_review.DEFAULT_MODEL_DEEP)


class ResponseTests(unittest.TestCase):
    def test_shape_errors_are_generic_and_fail_closed(self):
        with self.assertRaises(pr_review.LLMReviewError) as ctx:
            pr_review.extract_chat_content({"choices": [], "private": "provider detail"})
        self.assertIn("no choices", str(ctx.exception))
        self.assertNotIn("provider detail", str(ctx.exception))

        with self.assertRaisesRegex(pr_review.LLMReviewError, "empty content"):
            pr_review.extract_chat_content({"choices": [None]})

    def test_accepts_content_parts_and_marks_truncation(self):
        content = pr_review.extract_chat_content({"choices": [{"finish_reason": "length", "message": {"content": [{"text": "partial "}, {"text": "review"}]}}], "usage": {"completion_tokens_details": {"reasoning_tokens": 9}}})
        self.assertIn("partial review", content)
        self.assertIn("incomplete", content)

    def test_rejects_empty_non_200_and_invalid_json_responses(self):
        with self.assertRaisesRegex(pr_review.LLMReviewError, "empty content"):
            pr_review.extract_chat_content({"choices": [{"message": {"content": ""}}]})
        with mock.patch.dict(pr_review.os.environ, {"OPENAI_API_KEY": "test"}, clear=True), mock.patch.object(pr_review.requests, "post", return_value=FakeResponse(status_code=429, text="rate limited")):
            with self.assertRaises(pr_review.LLMReviewError) as ctx:
                pr_review.call_llm("diff", "default")
        self.assertIn("429", str(ctx.exception))
        self.assertNotIn("rate limited", str(ctx.exception))
        with mock.patch.dict(pr_review.os.environ, {"OPENAI_API_KEY": "test"}, clear=True), mock.patch.object(pr_review.requests, "post", return_value=InvalidJSONResponse()):
            with self.assertRaisesRegex(pr_review.LLMReviewError, "invalid JSON"):
                pr_review.call_llm("diff", "default")
        with mock.patch.dict(pr_review.os.environ, {"OPENAI_API_KEY": "test"}, clear=True), mock.patch.object(pr_review.requests, "post", return_value=FakeResponse(data=[])):
            with self.assertRaisesRegex(pr_review.LLMReviewError, "non-object JSON"):
                pr_review.call_llm("diff", "default")


if __name__ == "__main__":
    unittest.main()
