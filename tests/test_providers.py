"""Unit tests for the model-agnostic provider adapter layer.

Pure (no network, no web framework) — runs on base Python. Verifies both
translation directions for OpenAI-compatible and Anthropic-native providers,
including a full tool-call round-trip.
"""
import os
import sys
import json
import pathlib

PROJ = str(pathlib.Path(__file__).resolve().parents[1])
sys.path.insert(0, PROJ)

os.environ["ANTHROPIC_API_KEY"] = "sk-ant-test"
os.environ["OPENAI_TEST_KEY"] = "sk-openai-test"
os.environ["NULL_KEY"] = ""  # unset-style

from src.common.providers import get_adapter, OpenAIAdapter, AnthropicAdapter

OPENAI_CONF = {"type": "openai", "endpoint": "http://x/v1/chat/completions", "api_key_env": "OPENAI_TEST_KEY"}
LOCAL_CONF = {"type": "openai", "endpoint": "http://ollama/v1/chat/completions", "api_key_env": "NULL_KEY"}
ANTHROPIC_CONF = {"type": "anthropic", "endpoint": "https://api.anthropic.com/v1/messages",
                  "api_key_env": "ANTHROPIC_API_KEY", "anthropic_version": "2023-06-01", "max_tokens": 2048}

TOOLS = [{"type": "function", "function": {
    "name": "resource_filesystem", "description": "fs", "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}}}]

results = []
def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}  {detail if not cond else ''}")


# ---------------- adapter selection ----------------
print("=== adapter selection ===")
check("anthropic -> AnthropicAdapter", isinstance(get_adapter("anthropic"), AnthropicAdapter))
check("openai -> OpenAIAdapter", isinstance(get_adapter("openai"), OpenAIAdapter))
check("local -> OpenAIAdapter (default)", isinstance(get_adapter("local"), OpenAIAdapter))
check("unknown -> OpenAIAdapter (default)", isinstance(get_adapter("whatever"), OpenAIAdapter))

# ---------------- OpenAI adapter ----------------
print("=== OpenAI-compatible adapter ===")
oa = OpenAIAdapter()
url, headers, body = oa.build_request("gpt-4o", [{"role": "user", "content": "hi"}], TOOLS, OPENAI_CONF)
check("openai url", url == OPENAI_CONF["endpoint"])
check("openai bearer auth", headers.get("Authorization") == "Bearer sk-openai-test")
check("openai tools passthrough", body["tools"] == TOOLS and body["tool_choice"] == "auto")
# NULL_KEY -> no Authorization header
_, h2, _ = oa.build_request("mistral", [{"role": "user", "content": "hi"}], None, LOCAL_CONF)
check("null-key -> no auth header", "Authorization" not in h2)
# parse tool_calls (arguments as JSON string -> dict)
turn = oa.parse_turn({"choices": [{"message": {"role": "assistant", "content": None,
    "tool_calls": [{"id": "c1", "function": {"name": "resource_filesystem", "arguments": '{"path":"a.txt"}'}}]}}]})
check("openai parse tool name", turn["tool_calls"][0]["name"] == "resource_filesystem")
check("openai parse args -> dict", turn["tool_calls"][0]["arguments"] == {"path": "a.txt"})
check("openai to_openai_response passthrough", oa.to_openai_response({"x": 1}) == {"x": 1})

# ---------------- Anthropic adapter ----------------
print("=== Anthropic native adapter ===")
an = AnthropicAdapter()
msgs = [
    {"role": "system", "content": "You are helpful."},
    {"role": "user", "content": "read a.txt"},
]
url, headers, body = an.build_request("claude-opus-4-8", msgs, TOOLS, ANTHROPIC_CONF)
check("anthropic url", url == ANTHROPIC_CONF["endpoint"])
check("anthropic x-api-key header", headers.get("x-api-key") == "sk-ant-test")
check("anthropic version header", headers.get("anthropic-version") == "2023-06-01")
check("anthropic max_tokens required", body.get("max_tokens") == 2048)
check("anthropic system extracted", body.get("system") == "You are helpful.")
check("anthropic system removed from messages", all(m["role"] != "system" for m in body["messages"]))
check("anthropic tools -> input_schema", body["tools"][0]["input_schema"] == TOOLS[0]["function"]["parameters"]
      and body["tools"][0]["name"] == "resource_filesystem")

# parse an Anthropic tool_use turn -> normalized + OpenAI assistant msg
an_resp = {"id": "msg_1", "model": "claude-opus-4-8", "stop_reason": "tool_use",
           "content": [{"type": "text", "text": "let me read it"},
                       {"type": "tool_use", "id": "tu_1", "name": "resource_filesystem", "input": {"path": "a.txt"}}]}
turn = an.parse_turn(an_resp)
check("anthropic parse tool name", turn["tool_calls"][0]["name"] == "resource_filesystem")
check("anthropic parse args dict", turn["tool_calls"][0]["arguments"] == {"path": "a.txt"})
check("anthropic assistant_msg has openai tool_calls",
      turn["assistant_msg"]["tool_calls"][0]["function"]["name"] == "resource_filesystem")

# full round-trip: append assistant + tool result, rebuild -> anthropic tool_use + tool_result turns
history = list(msgs)
history.append(turn["assistant_msg"])
history.append({"role": "tool", "tool_call_id": "tu_1", "name": "resource_filesystem",
                "content": json.dumps({"content": "hello world"})})
_, _, body2 = an.build_request("claude-opus-4-8", history, TOOLS, ANTHROPIC_CONF)
am = body2["messages"]
has_tool_use = any(m["role"] == "assistant" and any(isinstance(b, dict) and b.get("type") == "tool_use" for b in m["content"]) for m in am)
has_tool_result = any(m["role"] == "user" and isinstance(m["content"], list)
                      and any(b.get("type") == "tool_result" and b.get("tool_use_id") == "tu_1" for b in m["content"]) for m in am)
check("round-trip: assistant tool_use block present", has_tool_use)
check("round-trip: user tool_result block present", has_tool_result)

# final text-only Anthropic response -> OpenAI chat.completion
final = {"id": "msg_2", "model": "claude-opus-4-8", "stop_reason": "end_turn",
         "content": [{"type": "text", "text": "The file says hello world."}],
         "usage": {"input_tokens": 12, "output_tokens": 7}}
oai = an.to_openai_response(final)
check("to_openai object type", oai["object"] == "chat.completion")
check("to_openai content", oai["choices"][0]["message"]["content"] == "The file says hello world.")
check("to_openai finish_reason mapped", oai["choices"][0]["finish_reason"] == "stop")
check("to_openai usage total", oai["usage"]["total_tokens"] == 19)

# ---------------- Bedrock (Claude on AWS, SigV4) ----------------
print("=== Bedrock adapter (Claude on AWS) ===")
from src.common.providers import BedrockAnthropicAdapter, VertexAnthropicAdapter, GeminiAdapter
os.environ["AWS_ACCESS_KEY_ID"] = "AKIATEST"
os.environ["AWS_SECRET_ACCESS_KEY"] = "secretkey"
check("bedrock adapter selected", isinstance(get_adapter("bedrock"), BedrockAnthropicAdapter))
check("aws alias -> bedrock", isinstance(get_adapter("aws"), BedrockAnthropicAdapter))
bd = get_adapter("bedrock")
url, headers, body = bd.build_request("anthropic.claude-opus-4-8", msgs, TOOLS,
                                      {"type": "bedrock", "region": "us-east-1"})
check("bedrock model in URL path", "/model/anthropic.claude-opus-4-8/invoke" in url)
check("bedrock no model in body", "model" not in body)
check("bedrock anthropic_version literal", body.get("anthropic_version") == "bedrock-2023-05-31")
check("bedrock SigV4 Authorization", headers.get("Authorization", "").startswith("AWS4-HMAC-SHA256"))
check("bedrock x-amz-date present", "x-amz-date" in headers)
# reuses Anthropic parsing
check("bedrock reuses anthropic parse", bd.parse_turn(an_resp)["tool_calls"][0]["name"] == "resource_filesystem")

# ---------------- Vertex (Claude on GCP) ----------------
print("=== Vertex adapter (Claude on GCP) ===")
check("vertex adapter selected", isinstance(get_adapter("vertex"), VertexAnthropicAdapter))
vx = get_adapter("vertex")
os.environ["GOOGLE_ACCESS_TOKEN"] = "ya29.test"
url, headers, body = vx.build_request("claude-opus-4-8", msgs, TOOLS,
                                      {"type": "vertex", "region": "us-east5", "project": "proj-123"})
check("vertex url rawPredict", url.endswith(":rawPredict") and "publishers/anthropic/models/claude-opus-4-8" in url)
check("vertex anthropic_version literal", body.get("anthropic_version") == "vertex-2023-10-16")
check("vertex bearer auth", headers.get("Authorization") == "Bearer ya29.test")

# ---------------- Gemini (native, different protocol) ----------------
print("=== Gemini adapter (native) ===")
os.environ["GEMINI_KEY"] = "AIza-test"
check("gemini via 'google' alias", isinstance(get_adapter("google"), GeminiAdapter))
gm = get_adapter("gemini")
url, headers, body = gm.build_request("gemini-2.0-flash",
    [{"role": "system", "content": "be terse"}, {"role": "user", "content": "list files"}],
    TOOLS, {"type": "gemini", "api_key_env": "GEMINI_KEY"})
check("gemini x-goog-api-key", headers.get("x-goog-api-key") == "AIza-test")
check("gemini model in URL", "models/gemini-2.0-flash:generateContent" in url)
check("gemini system_instruction", body["system_instruction"]["parts"][0]["text"] == "be terse")
check("gemini contents role user", body["contents"][0]["role"] == "user")
check("gemini function_declarations", body["tools"][0]["function_declarations"][0]["name"] == "resource_filesystem")
# parse a Gemini functionCall turn
g_resp = {"candidates": [{"content": {"parts": [{"functionCall": {"name": "resource_filesystem", "args": {"action": "list", "path": "."}}}]}, "finishReason": "STOP"}],
          "usageMetadata": {"promptTokenCount": 8, "candidatesTokenCount": 4}, "modelVersion": "gemini-2.0-flash"}
gt = gm.parse_turn(g_resp)
check("gemini parse functionCall", gt["tool_calls"][0]["name"] == "resource_filesystem" and gt["tool_calls"][0]["arguments"] == {"action": "list", "path": "."})
# final text -> openai
g_final = {"candidates": [{"content": {"parts": [{"text": "done"}]}, "finishReason": "STOP"}], "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1}}
go = gm.to_openai_response(g_final)
check("gemini to_openai shape", go["object"] == "chat.completion" and go["choices"][0]["message"]["content"] == "done" and go["usage"]["total_tokens"] == 4)

passed = sum(1 for _, ok in results if ok)
failed = len(results) - passed
print(f"\n==================== TOTAL: {passed} passed, {failed} failed ====================")
sys.exit(1 if failed else 0)
