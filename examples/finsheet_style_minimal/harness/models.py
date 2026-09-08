"""models.py — provider adapters + a cache whose key carries EVERY
answer-changing parameter.

Roster (PREREGISTRATION.md): gemini-3.1-pro-preview, gpt-5.2 (reasoning
medium), claude-opus-4-6 (extended thinking 8k). Claude requires temperature
1 when thinking is enabled; that value is in the key, not hidden.

Keys come from the environment, or from the KEY=value file named by
$FINSHEET_KEYS_FILE; they are never printed or written to the run directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

# Optional key file (KEY=value lines), named by an environment variable so no
# path is baked into shipped code. Absent -> keys must be in the environment.
MASTER_ENV = Path(os.environ.get("FINSHEET_KEYS_FILE", ""))


def _load_key(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if v:
        return v
    if str(MASTER_ENV) and MASTER_ENV.is_file():
        for line in MASTER_ENV.read_text(encoding="utf-8").splitlines():
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit(f"{name} not set in the environment (or in $FINSHEET_KEYS_FILE)")


@dataclass(frozen=True)
class ModelSpec:
    label: str
    provider: str  # anthropic | openai | google
    model: str
    temperature: float | None
    max_output_tokens: int
    reasoning: dict = field(default_factory=dict)  # provider-specific, in the key

    def key_fields(self) -> dict:
        return {
            "provider": self.provider,
            "model": self.model,
            "temperature": self.temperature,
            "max_output_tokens": self.max_output_tokens,
            "reasoning": self.reasoning,
        }


ROSTER: dict[str, ModelSpec] = {
    "gemini-3.1-pro": ModelSpec(
        label="gemini-3.1-pro",
        provider="google",
        model="gemini-3.1-pro-preview",
        temperature=0.0,
        max_output_tokens=8000,
        reasoning={"thinking": "default"},
    ),
    "gpt-5.2": ModelSpec(
        label="gpt-5.2",
        provider="openai",
        model="gpt-5.2",
        temperature=None,
        max_output_tokens=8000,
        reasoning={"effort": "medium"},
    ),
    "claude-opus-4.6": ModelSpec(
        label="claude-opus-4.6",
        provider="anthropic",
        model="claude-opus-4-6",
        temperature=1.0,
        max_output_tokens=12000,
        reasoning={"thinking_budget": 8000},
    ),
    # TRANSPORT FALLBACK for the pre-registered Claude arm: the same model id
    # through OpenRouter, used only while the direct Anthropic key has no
    # credit. Its own label so a row never passes for a direct-API row; the
    # provider is in the cache key.
    "claude-opus-4.6-openrouter": ModelSpec(
        label="claude-opus-4.6-openrouter",
        provider="openrouter",
        model="anthropic/claude-opus-4.6",
        temperature=1.0,
        max_output_tokens=12000,
        reasoning={"thinking_budget": 8000},
    ),
    # Cheap smoke models for harness debugging; NOT in the pre-registered roster.
    "gpt-5.4-mini": ModelSpec(
        label="gpt-5.4-mini",
        provider="openai",
        model="gpt-5.4-mini",
        temperature=None,
        max_output_tokens=4000,
        reasoning={"effort": "low"},
    ),
    "gemini-3.5-flash": ModelSpec(
        label="gemini-3.5-flash",
        provider="google",
        model="gemini-3.5-flash",
        temperature=0.0,
        max_output_tokens=4000,
        reasoning={"thinking": "default"},
    ),
    "claude-haiku-4.5": ModelSpec(
        label="claude-haiku-4.5",
        provider="anthropic",
        model="claude-haiku-4-5-20251001",
        temperature=0.0,
        max_output_tokens=4000,
        reasoning={},
    ),
}


@dataclass
class Completion:
    text: str
    usage: dict
    model_reported: str
    cached: bool
    latency_s: float


class Cache:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def key(spec: ModelSpec, system: str, user: str, sample_idx: int) -> str:
        doc = {
            "system": system,
            "user": user,
            "sample_idx": sample_idx,
            **spec.key_fields(),
        }
        return hashlib.sha256(
            json.dumps(doc, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

    def get(self, k: str) -> dict | None:
        p = self.root / f"{k}.json"
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))
        return None

    def put(self, k: str, doc: dict) -> None:
        (self.root / f"{k}.json").write_text(
            json.dumps(doc, indent=1, ensure_ascii=False), encoding="utf-8"
        )


class Client:
    def __init__(self, cache: Cache):
        self.cache = cache
        self._anthropic = None
        self._openai = None
        self._google = None
        self._openrouter = None

    # -- providers ---------------------------------------------------------
    def _call_anthropic(
        self, spec: ModelSpec, system: str, user: str
    ) -> tuple[str, dict, str]:
        if self._anthropic is None:
            import anthropic

            self._anthropic = anthropic.Anthropic(
                api_key=_load_key("ANTHROPIC_API_KEY")
            )
        kw: dict = dict(
            model=spec.model,
            max_tokens=spec.max_output_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        if spec.reasoning.get("thinking_budget"):
            kw["thinking"] = {
                "type": "enabled",
                "budget_tokens": int(spec.reasoning["thinking_budget"]),
            }
        if spec.temperature is not None:
            kw["temperature"] = spec.temperature
        r = self._anthropic.messages.create(**kw)
        text = "".join(
            getattr(b, "text", "")
            for b in r.content
            if getattr(b, "type", "") == "text"
        )
        usage = {
            "input_tokens": r.usage.input_tokens,
            "output_tokens": r.usage.output_tokens,
        }
        return text, usage, r.model

    def _call_openai(
        self, spec: ModelSpec, system: str, user: str
    ) -> tuple[str, dict, str]:
        if self._openai is None:
            import openai

            self._openai = openai.OpenAI(api_key=_load_key("OPENAI_API_KEY"))
        kw: dict = dict(
            model=spec.model,
            max_output_tokens=spec.max_output_tokens,
            input=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        if spec.reasoning.get("effort"):
            kw["reasoning"] = {"effort": spec.reasoning["effort"]}
        if spec.temperature is not None:
            kw["temperature"] = spec.temperature
        r = self._openai.responses.create(**kw)
        text = r.output_text
        u = r.usage
        usage = {
            "input_tokens": u.input_tokens,
            "output_tokens": u.output_tokens,
            "reasoning_tokens": getattr(
                getattr(u, "output_tokens_details", None), "reasoning_tokens", None
            ),
        }
        return text, usage, r.model

    def _call_google(
        self, spec: ModelSpec, system: str, user: str
    ) -> tuple[str, dict, str]:
        if self._google is None:
            from google import genai

            self._google = genai.Client(api_key=_load_key("GOOGLE_AI_STUDIO_KEY"))
        from google.genai import types

        cfg = types.GenerateContentConfig(
            system_instruction=system,
            temperature=spec.temperature,
            max_output_tokens=spec.max_output_tokens,
            response_mime_type="application/json",
        )
        r = self._google.models.generate_content(
            model=spec.model, contents=user, config=cfg
        )
        text = r.text or ""
        um = r.usage_metadata
        usage = {
            "input_tokens": getattr(um, "prompt_token_count", None),
            "output_tokens": getattr(um, "candidates_token_count", None),
            "reasoning_tokens": getattr(um, "thoughts_token_count", None),
        }
        return text, usage, getattr(r, "model_version", spec.model) or spec.model

    def _call_openrouter(
        self, spec: ModelSpec, system: str, user: str
    ) -> tuple[str, dict, str]:
        """OpenAI-compatible chat completions on openrouter.ai. Anthropic
        extended thinking is requested through OpenRouter's `reasoning`
        parameter; the response's usage reports reasoning tokens when the
        upstream provider returns them."""
        if self._openrouter is None:
            import openai

            self._openrouter = openai.OpenAI(
                api_key=_load_key("OPENROUTER_API_KEY"),
                base_url="https://openrouter.ai/api/v1",
            )
        kw: dict = dict(
            model=spec.model,
            max_tokens=spec.max_output_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        if spec.temperature is not None:
            kw["temperature"] = spec.temperature
        extra: dict = {}
        if spec.reasoning.get("thinking_budget"):
            extra["reasoning"] = {"max_tokens": int(spec.reasoning["thinking_budget"])}
        r = self._openrouter.chat.completions.create(**kw, extra_body=extra)
        text = r.choices[0].message.content or ""
        u = r.usage
        details = getattr(u, "completion_tokens_details", None)
        usage = {
            "input_tokens": getattr(u, "prompt_tokens", None),
            "output_tokens": getattr(u, "completion_tokens", None),
            "reasoning_tokens": getattr(details, "reasoning_tokens", None) if details else None,
        }
        return text, usage, r.model

    # -- public --------------------------------------------------------------
    def complete(
        self,
        spec: ModelSpec,
        system: str,
        user: str,
        *,
        sample_idx: int = 0,
        retries: int = 4,
    ) -> Completion:
        k = Cache.key(spec, system, user, sample_idx)
        hit = self.cache.get(k)
        if hit is not None:
            return Completion(
                hit["text"], hit["usage"], hit["model_reported"], True, 0.0
            )
        fn = {
            "anthropic": self._call_anthropic,
            "openai": self._call_openai,
            "google": self._call_google,
            "openrouter": self._call_openrouter,
        }[spec.provider]
        delay = 5.0
        last: Exception | None = None
        for attempt in range(retries):
            t0 = time.time()
            try:
                text, usage, reported = fn(spec, system, user)
                lat = time.time() - t0
                doc = {
                    "key_fields": spec.key_fields(),
                    "sample_idx": sample_idx,
                    "text": text,
                    "usage": usage,
                    "model_reported": reported,
                    "latency_s": lat,
                    "ts": time.time(),
                }
                self.cache.put(k, doc)
                return Completion(text, usage, reported, False, lat)
            except Exception as exc:  # noqa: BLE001 — provider errors are retried, then surfaced
                last = exc
                name = type(exc).__name__
                # A 4xx other than rate-limit is not transient: no key, no
                # credit, bad model id. Retrying it with backoff turns a
                # 1-second refusal into a 75-second one per cell.
                if any(t in name for t in ("BadRequest", "Authentication", "PermissionDenied", "NotFound", "InvalidArgument")):
                    break
                time.sleep(delay)
                delay *= 2
        raise RuntimeError(f"{spec.label}: {type(last).__name__}: {last}")

    def count_tokens_anthropic(self, spec: ModelSpec, system: str, user: str) -> int:
        if self._anthropic is None:
            import anthropic

            self._anthropic = anthropic.Anthropic(
                api_key=_load_key("ANTHROPIC_API_KEY")
            )
        try:
            r = self._anthropic.messages.count_tokens(
                model=spec.model, system=system, messages=[{"role": "user", "content": user}]
            )
            return int(r.input_tokens)
        except Exception as exc:  # noqa: BLE001 — a dead key must not block the other providers' measure
            print(f"  (anthropic count_tokens unavailable: {type(exc).__name__})")
            return -1
