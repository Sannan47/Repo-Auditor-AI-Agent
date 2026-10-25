"""Basic provider SDK only: orchestration lives in auditor.engine."""

import os
from dataclasses import dataclass

from auditor.repository import AuditError


@dataclass(frozen=True)
class Settings:
    api_key: str
    model: str
    base_url: str | None = None
    max_rounds: int = 30
    timeout: float = 60

    @classmethod
    def from_environment(cls):
        key = os.getenv("LLM_API_KEY", "").strip()
        model = os.getenv("LLM_MODEL", "").strip()
        if not key or not model:
            raise AuditError("Set LLM_API_KEY and LLM_MODEL in your environment or local .env file")
        try:
            rounds = int(os.getenv("AGENT_MAX_ROUNDS", "30"))
            timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "60"))
            if not 1 <= rounds <= 100 or not 1 <= timeout <= 300:
                raise ValueError
        except ValueError as exc:
            raise AuditError("AGENT_MAX_ROUNDS must be 1..100 and LLM_TIMEOUT_SECONDS must be 1..300") from exc
        return cls(key, model, os.getenv("LLM_BASE_URL") or None, rounds, timeout)


class OpenAICompatibleProvider:
    def __init__(self, settings: Settings):
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise AuditError("Install dependencies with: python -m pip install -r requirements.txt") from exc
        self.model = settings.model
        self.client = OpenAI(api_key=settings.api_key, base_url=settings.base_url,
                             timeout=settings.timeout, max_retries=2)

    def complete(self, messages, tools):
        try:
            response = self.client.chat.completions.create(
                model=self.model, messages=messages, tools=tools, tool_choice="auto",
            )
            if not response.choices:
                raise AuditError("LLM returned no choices")
            choice = response.choices[0]
            if choice.finish_reason in {"length", "content_filter"}:
                raise AuditError("LLM output was incomplete or filtered; no report was produced")
            message = choice.message
            result = {"role": "assistant", "content": message.content}
            if message.tool_calls:
                result["tool_calls"] = [call.model_dump(exclude_none=True) for call in message.tool_calls]
            return result
        except AuditError:
            raise
        except Exception as exc:
            # Provider exception text can include request content or credentials.
            code = getattr(exc, "status_code", None)
            detail = f" (HTTP {code})" if isinstance(code, int) else ""
            raise AuditError(f"LLM request failed{detail}. Check API credentials, model access, endpoint, quota, and network connectivity.") from None
