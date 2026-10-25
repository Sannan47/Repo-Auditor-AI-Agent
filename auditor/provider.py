"""Basic provider SDK only: orchestration lives in auditor.engine."""

import os
import math
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from auditor.repository import AuditError


@dataclass(frozen=True)
class Settings:
    api_key: str
    model: str
    base_url: str | None = None
    max_rounds: int = 30
    timeout: float = 60
    max_retries: int = 4
    retry_base: float = 5

    @classmethod
    def from_environment(cls):
        key = os.getenv("LLM_API_KEY", "").strip()
        model = os.getenv("LLM_MODEL", "").strip()
        if not key or not model:
            raise AuditError("Set LLM_API_KEY and LLM_MODEL in your environment or local .env file")
        try:
            rounds = int(os.getenv("AGENT_MAX_ROUNDS", "30"))
            timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "60"))
            retries = int(os.getenv('LLM_MAX_RETRIES', '4'))
            retry_base = float(os.getenv('LLM_RETRY_BASE_SECONDS', '5'))
            if not 1 <= rounds <= 100 or not 1 <= timeout <= 300 or not 0 <= retries <= 8 or not 0.1 <= retry_base <= 60:
                raise ValueError
        except ValueError as exc:
            raise AuditError("AGENT_MAX_ROUNDS must be 1..100, LLM_TIMEOUT_SECONDS 1..300, LLM_MAX_RETRIES 0..8, and LLM_RETRY_BASE_SECONDS 0.1..60") from exc
        return cls(key, model, os.getenv("LLM_BASE_URL") or None, rounds, timeout, retries, retry_base)


def _details(exc):
    body = getattr(exc, 'body', None)
    if not isinstance(body, dict):
        return []
    error = body.get('error', body)
    return error.get('details', []) if isinstance(error, dict) and isinstance(error.get('details', []), list) else []


def _quota_is_permanent(exc):
    for detail in _details(exc):
        if not isinstance(detail, dict):
            continue
        violations = detail.get('violations', [])
        if not isinstance(violations, list):
            continue
        for violation in violations:
            if not isinstance(violation, dict):
                continue
            quota = str(violation.get('quotaId', '')).lower().replace('_', '').replace('-', '')
            if 'perday' in quota or str(violation.get('quotaValue', '')) == '0':
                return True
    return False


def _retryable(exc):
    status = getattr(exc, 'status_code', None)
    if isinstance(status, int):
        return status in {408, 409, 429} or 500 <= status <= 599
    try:
        from openai import APIConnectionError, APITimeoutError
        return isinstance(exc, (APIConnectionError, APITimeoutError))
    except ImportError:
        return False


def _retry_delay(exc, attempt, base):
    response = getattr(exc, 'response', None)
    headers = getattr(response, 'headers', {})
    delays = []
    raw = headers.get('retry-after')
    if raw is not None:
        try:
            delays.append(float(raw))
        except (ValueError, TypeError):
            try:
                date = parsedate_to_datetime(str(raw))
                if date.tzinfo is None:
                    date = date.replace(tzinfo=timezone.utc)
                delays.append((date - datetime.now(timezone.utc)).total_seconds())
            except (ValueError, TypeError, OverflowError):
                pass
    try:
        if headers.get('retry-after-ms') is not None:
            delays.append(float(headers['retry-after-ms']) / 1000)
    except (ValueError, TypeError):
        pass
    for detail in _details(exc):
        if isinstance(detail, dict) and 'RetryInfo' in str(detail.get('@type', '')):
            try:
                delays.append(float(str(detail.get('retryDelay', '')).removesuffix('s')))
            except ValueError:
                pass
    delays = [delay for delay in delays if math.isfinite(delay) and delay >= 0]
    if delays:
        delay = max(delays)
        if delay > 60:
            raise AuditError('LLM requested a retry wait longer than 60 seconds. Check project quota or retry the audit later.')
        return delay
    return min(60, base * 2 ** attempt + random.uniform(0, base))


class OpenAICompatibleProvider:
    def __init__(self, settings: Settings):
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise AuditError("Install dependencies with: python -m pip install -r requirements.txt") from exc
        self.model = settings.model
        self.max_retries, self.retry_base, self.retry_events = settings.max_retries, settings.retry_base, []
        self.client = OpenAI(api_key=settings.api_key, base_url=settings.base_url,
                             timeout=settings.timeout, max_retries=0)

    def complete(self, messages, tools):
        retries = getattr(self, 'max_retries', 0)
        for attempt in range(retries + 1):
            try:
                return self._complete_once(messages, tools)
            except AuditError:
                raise
            except Exception as exc:
                code = getattr(exc, 'status_code', None)
                if code == 429 and _quota_is_permanent(exc):
                    raise AuditError('LLM daily or zero project quota is exhausted. Check API project limits; short retries cannot restore this quota.') from None
                if attempt < retries and _retryable(exc):
                    delay = _retry_delay(exc, attempt, getattr(self, 'retry_base', 5))
                    if not hasattr(self, 'retry_events'):
                        self.retry_events = []
                    self.retry_events.append({'attempt': attempt + 1, 'status': code, 'delay_seconds': delay})
                    time.sleep(delay)
                    continue
                # Never echo provider errors: they can contain credentials/content.
                detail = f' (HTTP {code})' if isinstance(code, int) else ''
                raise AuditError(f'LLM request failed{detail} after {attempt + 1} attempt(s). Check API credentials, model access, endpoint, quota, and network connectivity.') from None

    def drain_retry_events(self):
        events = getattr(self, 'retry_events', [])
        self.retry_events = []
        return events

    def _complete_once(self, messages, tools):
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
