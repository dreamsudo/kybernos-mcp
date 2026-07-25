"""Model-provider adapter layer — makes the gateway model-agnostic.

The gateway's edge is ALWAYS OpenAI-Chat-Completions-compatible (clients are
unchanged regardless of backend). Each adapter translates that canonical form
to/from a provider's native wire protocol:

  - OpenAIAdapter    : OpenAI + any OpenAI-compatible server (Ollama, vLLM,
                       LM Studio, llama.cpp, LiteLLM, Together, Groq, ...).
                       Near-passthrough; the default for every provider type
                       that isn't "anthropic".
  - AnthropicAdapter : Anthropic Messages API (native /v1/messages, x-api-key
                       auth, tool_use content blocks). The first-class,
                       optimized path.

CRITICAL: adapters ONLY touch the model wire format. The security pipeline
(RBAC, capability tokens, JSON-Schema validation, firewall, egress DLP, audit)
operates on the normalized {principal, resource, payload} downstream and is
completely provider-independent. Adding a provider never changes the ZTA/NIST
controls.

Canonical internal representations:
  - history : OpenAI chat messages  [{role, content, tool_calls?}, ...]
  - tools   : OpenAI function tools  [{type: function, function: {name, description, parameters}}]

Adapter contract:
  build_request(model_id, messages, tools, provider_conf) -> (url, headers, body)
  parse_turn(raw) -> {content, tool_calls: [{id,name,arguments(dict)}], assistant_msg(openai)}
  to_openai_response(raw) -> OpenAI ChatCompletion dict   (final client-facing reply)
"""
import os
import json
import hmac
import hashlib
import logging
import datetime as _dt
import urllib.parse

logger = logging.getLogger("providers")


def _provider_key(provider_conf: dict) -> str:
    return os.getenv(provider_conf.get("api_key_env", ""), "")


def serialize_body(body: dict) -> bytes:
    """Canonical JSON bytes for an upstream request body.

    The gateway transmits *exactly* these bytes (see service_gateway._call_upstream),
    which is what makes AWS SigV4 correct: the Bedrock adapter signs the sha256 of
    this same serialization, so the signed payload hash matches the bytes on the
    wire. Re-serializing with httpx's ``json=`` would sign one byte-string and send
    another -> SignatureDoesNotMatch (403). Keep signer and sender on this function.
    """
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# OpenAI-compatible adapter (default for openai / local / ollama / vllm / ...)
# ---------------------------------------------------------------------------
class OpenAIAdapter:
    name = "openai"

    def build_request(self, model_id, messages, tools, provider_conf):
        body = {"model": model_id, "messages": messages, "stream": False}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        headers = {"Content-Type": "application/json"}
        key = _provider_key(provider_conf)
        if key and key != "NULL_KEY":
            headers["Authorization"] = f"Bearer {key}"
        return provider_conf["endpoint"], headers, body

    def parse_turn(self, raw):
        choices = raw.get("choices", [])
        if not choices:
            return {"content": None, "tool_calls": [], "assistant_msg": None}
        msg = choices[0].get("message", {}) or {}
        tool_calls = []
        for c in msg.get("tool_calls", []) or []:
            fn = c.get("function", {})
            args = fn.get("arguments", "{}")
            try:
                parsed = args if isinstance(args, dict) else json.loads(args or "{}")
            except ValueError:
                parsed = {}
            tool_calls.append({"id": c.get("id", "call_null"), "name": fn.get("name"), "arguments": parsed})
        return {"content": msg.get("content"), "tool_calls": tool_calls, "assistant_msg": msg}

    def to_openai_response(self, raw):
        return raw  # already OpenAI-shaped


# ---------------------------------------------------------------------------
# Anthropic native adapter (Messages API) — the optimized path
# ---------------------------------------------------------------------------
_STOP_MAP = {"end_turn": "stop", "max_tokens": "length", "tool_use": "tool_calls",
            "stop_sequence": "stop", "refusal": "content_filter", "pause_turn": "stop"}


class AnthropicAdapter:
    name = "anthropic"

    # --- canonical(OpenAI) -> Anthropic ---
    @staticmethod
    def _messages_to_anthropic(messages):
        system_parts, out, pending = [], [], []

        def flush():
            if pending:
                out.append({"role": "user", "content": list(pending)})
                pending.clear()

        for m in messages:
            role = m.get("role")
            content = m.get("content")
            if role == "system":
                if isinstance(content, str):
                    system_parts.append(content)
                elif isinstance(content, list):
                    system_parts.append(" ".join(b.get("text", "") for b in content if isinstance(b, dict)))
                continue
            if role == "tool":
                pending.append({
                    "type": "tool_result",
                    "tool_use_id": m.get("tool_call_id", "call_null"),
                    "content": content if isinstance(content, str) else json.dumps(content),
                })
                continue
            flush()
            if role == "assistant":
                blocks = []
                if content:
                    blocks.append({"type": "text", "text": content if isinstance(content, str) else json.dumps(content)})
                for tc in m.get("tool_calls", []) or []:
                    fn = tc.get("function", {})
                    args = fn.get("arguments", "{}")
                    try:
                        inp = args if isinstance(args, dict) else json.loads(args or "{}")
                    except ValueError:
                        inp = {}
                    blocks.append({"type": "tool_use", "id": tc.get("id", "call_null"), "name": fn.get("name"), "input": inp})
                out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": ""}]})
            else:  # user / anything else
                if isinstance(content, (str, list)):
                    out.append({"role": "user", "content": content})
                else:
                    out.append({"role": "user", "content": json.dumps(content)})
        flush()
        system = "\n".join(p for p in system_parts if p) or None
        return system, out

    @staticmethod
    def _tools_to_anthropic(tools):
        out = []
        for t in tools or []:
            fn = t.get("function", {})
            out.append({"name": fn.get("name"), "description": fn.get("description", ""),
                        "input_schema": fn.get("parameters", {"type": "object"})})
        return out

    def build_request(self, model_id, messages, tools, provider_conf):
        system, an_messages = self._messages_to_anthropic(messages)
        body = {
            "model": model_id,
            "max_tokens": int(provider_conf.get("max_tokens", 4096)),
            "messages": an_messages,
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = self._tools_to_anthropic(tools)
        # Anthropic optimizations, opt-in via provider config.
        if provider_conf.get("thinking"):
            body["thinking"] = {"type": "adaptive"}
        if provider_conf.get("effort"):
            body.setdefault("output_config", {})["effort"] = provider_conf["effort"]
        headers = {
            "content-type": "application/json",
            "x-api-key": _provider_key(provider_conf),
            "anthropic-version": provider_conf.get("anthropic_version", "2023-06-01"),
        }
        return provider_conf.get("endpoint", "https://api.anthropic.com/v1/messages"), headers, body

    # --- Anthropic -> canonical(OpenAI) ---
    def parse_turn(self, raw):
        text_parts, tool_calls, oai_tc = [], [], []
        for b in raw.get("content", []) or []:
            if b.get("type") == "text":
                text_parts.append(b.get("text", ""))
            elif b.get("type") == "tool_use":
                tool_calls.append({"id": b.get("id", "call_null"), "name": b.get("name"), "arguments": b.get("input") or {}})
                oai_tc.append({"id": b.get("id", "call_null"), "type": "function",
                               "function": {"name": b.get("name"), "arguments": json.dumps(b.get("input") or {})}})
        text = "".join(text_parts)
        assistant = {"role": "assistant", "content": text or None}
        if oai_tc:
            assistant["tool_calls"] = oai_tc
        return {"content": text, "tool_calls": tool_calls, "assistant_msg": assistant}

    def to_openai_response(self, raw):
        text = "".join(b.get("text", "") for b in raw.get("content", []) or [] if b.get("type") == "text")
        usage = raw.get("usage", {}) or {}
        pt, ct = usage.get("input_tokens", 0), usage.get("output_tokens", 0)
        return {
            "id": raw.get("id", "chatcmpl-anthropic"),
            "object": "chat.completion",
            "model": raw.get("model"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                         "finish_reason": _STOP_MAP.get(raw.get("stop_reason"), "stop")}],
            "usage": {"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": pt + ct},
        }


# ---------------------------------------------------------------------------
# AWS SigV4 (self-contained) — used by the Bedrock adapter
# ---------------------------------------------------------------------------
def _sigv4_headers(method, url, body: bytes, region, service, ak, sk, token=None):
    p = urllib.parse.urlparse(url)
    host = p.netloc
    canonical_uri = urllib.parse.quote(p.path or "/", safe="/-_.~%")
    canonical_qs = "&".join(sorted(p.query.split("&"))) if p.query else ""
    now = _dt.datetime.now(_dt.timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date"
    canonical_headers = (f"content-type:application/json\nhost:{host}\n"
                         f"x-amz-content-sha256:{payload_hash}\nx-amz-date:{amzdate}\n")
    canonical_request = "\n".join([method, canonical_uri, canonical_qs, canonical_headers,
                                   signed_headers, payload_hash])
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                         hashlib.sha256(canonical_request.encode()).hexdigest()])

    def _hmac(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()
    k = _hmac(("AWS4" + sk).encode(), datestamp)
    k = _hmac(k, region); k = _hmac(k, service); k = _hmac(k, "aws4_request")
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    headers = {
        "content-type": "application/json",
        "x-amz-date": amzdate,
        "x-amz-content-sha256": payload_hash,
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
                          f"SignedHeaders={signed_headers}, Signature={sig}"),
    }
    if token:
        headers["x-amz-security-token"] = token
    return headers


# ---------------------------------------------------------------------------
# Amazon Bedrock — Claude via the Anthropic Messages shape (native)
#   provider_conf: {type: bedrock, region, model in URL, SigV4 or bearer}
# ---------------------------------------------------------------------------
class BedrockAnthropicAdapter(AnthropicAdapter):
    name = "bedrock"

    def build_request(self, model_id, messages, tools, provider_conf):
        # Reuse Anthropic body translation, then adapt for Bedrock:
        #  - model goes in the URL, not the body
        #  - anthropic_version is a bedrock literal in the body
        _, _, body = super().build_request(model_id, messages, tools, provider_conf)
        body.pop("model", None)
        body["anthropic_version"] = provider_conf.get("anthropic_version", "bedrock-2023-05-31")
        region = provider_conf.get("region", "us-east-1")
        endpoint = provider_conf.get("endpoint") or \
            f"https://bedrock-runtime.{region}.amazonaws.com/model/{{model}}/invoke"
        url = endpoint.replace("{model}", urllib.parse.quote(model_id, safe=""))
        # Sign the EXACT bytes the gateway will transmit (serialize_body), not a
        # re-serialization — otherwise the signed payload hash != the wire body.
        raw = serialize_body(body)
        ak = os.getenv(provider_conf.get("aws_access_key_env", "AWS_ACCESS_KEY_ID"), "")
        sk = os.getenv(provider_conf.get("aws_secret_key_env", "AWS_SECRET_ACCESS_KEY"), "")
        if ak and sk:  # native SigV4
            token = os.getenv("AWS_SESSION_TOKEN") or None
            headers = _sigv4_headers("POST", url, raw, region, "bedrock", ak, sk, token)
        else:          # gateway/proxy fronting Bedrock with a bearer token
            headers = {"content-type": "application/json"}
            key = _provider_key(provider_conf)
            if key and key != "NULL_KEY":
                headers["Authorization"] = f"Bearer {key}"
        return url, headers, body
    # parse_turn / to_openai_response inherited (Bedrock returns the Messages shape)


# ---------------------------------------------------------------------------
# Google Vertex AI — Claude via the Anthropic Messages shape (native)
# ---------------------------------------------------------------------------
class VertexAnthropicAdapter(AnthropicAdapter):
    name = "vertex"

    def build_request(self, model_id, messages, tools, provider_conf):
        _, _, body = super().build_request(model_id, messages, tools, provider_conf)
        body.pop("model", None)
        body["anthropic_version"] = provider_conf.get("anthropic_version", "vertex-2023-10-16")
        region = provider_conf.get("region", "us-east5")
        project = provider_conf.get("project", "")
        endpoint = provider_conf.get("endpoint") or (
            f"https://{region}-aiplatform.googleapis.com/v1/projects/{project}/locations/"
            f"{region}/publishers/anthropic/models/{{model}}:rawPredict")
        url = endpoint.replace("{model}", urllib.parse.quote(model_id, safe=""))
        # Vertex uses a Google OAuth access token (ADC / gcloud); supply via api_key_env
        # or GOOGLE_ACCESS_TOKEN. Refreshing ADC is out of scope for the gateway.
        token = _provider_key(provider_conf) or os.getenv("GOOGLE_ACCESS_TOKEN", "")
        headers = {"content-type": "application/json", "Authorization": f"Bearer {token}"}
        return url, headers, body


# ---------------------------------------------------------------------------
# Google Gemini (generativelanguage API) — a genuinely different wire protocol.
# Best "add a brand-new adapter" reference.
# ---------------------------------------------------------------------------
_GEMINI_FINISH = {"STOP": "stop", "MAX_TOKENS": "length", "SAFETY": "content_filter"}


class GeminiAdapter:
    name = "gemini"

    def build_request(self, model_id, messages, tools, provider_conf):
        system_parts, contents = [], []
        pending_fn_results = []

        def flush_results():
            if pending_fn_results:
                contents.append({"role": "user", "parts": list(pending_fn_results)})
                pending_fn_results.clear()

        for m in messages:
            role, content = m.get("role"), m.get("content")
            if role == "system":
                if isinstance(content, str):
                    system_parts.append(content)
                elif isinstance(content, list):  # OpenAI content-parts form
                    system_parts.append(
                        "\n".join(b.get("text", "") for b in content if isinstance(b, dict)))
                elif content is not None:
                    system_parts.append(str(content))
                continue
            if role == "tool":
                pending_fn_results.append({"functionResponse": {
                    "name": m.get("name", "tool"),
                    "response": {"content": content if isinstance(content, str) else json.dumps(content)}}})
                continue
            flush_results()
            if role == "assistant":
                parts = []
                if content:
                    parts.append({"text": content if isinstance(content, str) else json.dumps(content)})
                for tc in m.get("tool_calls", []) or []:
                    fn = tc.get("function", {})
                    args = fn.get("arguments", "{}")
                    try:
                        a = args if isinstance(args, dict) else json.loads(args or "{}")
                    except ValueError:
                        a = {}
                    parts.append({"functionCall": {"name": fn.get("name"), "args": a}})
                contents.append({"role": "model", "parts": parts or [{"text": ""}]})
            else:
                contents.append({"role": "user", "parts": [{"text": content if isinstance(content, str) else json.dumps(content)}]})
        flush_results()

        body = {"contents": contents}
        if system_parts:
            body["system_instruction"] = {"parts": [{"text": "\n".join(system_parts)}]}
        if tools:
            body["tools"] = [{"function_declarations": [
                {"name": t["function"]["name"], "description": t["function"].get("description", ""),
                 "parameters": t["function"].get("parameters", {"type": "object"})} for t in tools]}]
        endpoint = provider_conf.get("endpoint",
            "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent")
        url = endpoint.replace("{model}", urllib.parse.quote(model_id, safe=""))
        headers = {"content-type": "application/json", "x-goog-api-key": _provider_key(provider_conf)}
        return url, headers, body

    def parse_turn(self, raw):
        cands = raw.get("candidates", [])
        parts = ((cands[0].get("content") or {}).get("parts") or [] if cands else [])
        text_parts, tool_calls, oai_tc = [], [], []
        for i, p in enumerate(parts):
            if "text" in p:
                text_parts.append(p["text"])
            elif "functionCall" in p:
                fc = p["functionCall"]
                cid = f"call_{i}_{fc.get('name', 'fn')}"
                tool_calls.append({"id": cid, "name": fc.get("name"), "arguments": fc.get("args") or {}})
                oai_tc.append({"id": cid, "type": "function",
                               "function": {"name": fc.get("name"), "arguments": json.dumps(fc.get("args") or {})}})
        text = "".join(text_parts)
        assistant = {"role": "assistant", "content": text or None}
        if oai_tc:
            assistant["tool_calls"] = oai_tc
        return {"content": text, "tool_calls": tool_calls, "assistant_msg": assistant}

    def to_openai_response(self, raw):
        cands = raw.get("candidates", [])
        parts = ((cands[0].get("content") or {}).get("parts") or [] if cands else [])
        text = "".join(p.get("text", "") for p in parts if "text" in p)
        um = raw.get("usageMetadata", {}) or {}
        pt, ct = um.get("promptTokenCount", 0), um.get("candidatesTokenCount", 0)
        return {
            "id": "chatcmpl-gemini", "object": "chat.completion", "model": raw.get("modelVersion"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                         "finish_reason": _GEMINI_FINISH.get(cands[0].get("finishReason") if cands else None, "stop")}],
            "usage": {"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": pt + ct},
        }


_ADAPTERS = {
    "anthropic": AnthropicAdapter(),
    "bedrock": BedrockAnthropicAdapter(),
    "vertex": VertexAnthropicAdapter(),
    "gemini": GeminiAdapter(),
    "openai": OpenAIAdapter(),
}
# Aliases -> canonical adapter key
_ALIASES = {"anthropic_bedrock": "bedrock", "aws": "bedrock", "anthropic_vertex": "vertex",
            "gcp": "vertex", "google": "gemini", "googleai": "gemini"}


def get_adapter(provider_type: str):
    """Select the wire adapter for a provider type.

    anthropic -> native Messages API   | bedrock -> Claude on AWS (SigV4)
    vertex    -> Claude on GCP          | gemini  -> Google Gemini (native)
    everything else -> OpenAI-compatible (OpenAI, Ollama, vLLM, LiteLLM, ...).
    """
    t = (provider_type or "").lower()
    t = _ALIASES.get(t, t)
    return _ADAPTERS.get(t, _ADAPTERS["openai"])
