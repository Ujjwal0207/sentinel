"""
SENTINEL Google Gemini AI Agent + PayPal Sandbox Zero-Trust Orchestrator.

Pipeline:
1. Google Gemini (`generateContent` + Function Calling) converts a user/workflow prompt
   into a structured PayPal Sandbox tool call (payout, order, or refund).
2. Before ANY money moves, SENTINEL signs the exact JSON request (KYA HMAC-SHA256 +
   optional Google AP2 User Intent Mandate commitment) and submits it to the Go Edge
   Gateway (`/enforce`) for fail-closed policy, guardrail, semantic, velocity, and RBAC checks.
3. ONLY if SENTINEL returns HTTP 200 ALLOW does the PayPalSandboxClient execute the
   transaction against `https://api-m.sandbox.paypal.com`.
"""

import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple

import requests

try:
    from paypal_sandbox import PayPalSandboxClient, PayPalSandboxError
except ImportError:
    from python_workers.paypal_sandbox import PayPalSandboxClient, PayPalSandboxError

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_GEMINI_MODEL = "gemini-3.8-flash"

TOOL_TO_SENTINEL_ACTION = {
    "paypal_payout": "PAYPAL_PAYOUT",
    "paypal_create_order": "PAYPAL_CREATE_ORDER",
    "paypal_refund_capture": "PAYPAL_REFUND",
}

GEMINI_PAYPAL_TOOLS = [
    {
        "functionDeclarations": [
            {
                "name": "paypal_payout",
                "description": "Send a PayPal Sandbox payout to a recipient email address.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "recipient_email": {
                            "type": "STRING",
                            "description": "PayPal recipient email address (e.g. sb-buyer@personal.example.com).",
                        },
                        "amount": {
                            "type": "NUMBER",
                            "description": "Numeric payment amount.",
                        },
                        "currency": {
                            "type": "STRING",
                            "description": "3-letter ISO-4217 currency code, e.g. USD.",
                        },
                        "note": {
                            "type": "STRING",
                            "description": "Short memo or payout note.",
                        },
                    },
                    "required": ["recipient_email", "amount", "currency"],
                },
            },
            {
                "name": "paypal_create_order",
                "description": "Create a PayPal Sandbox Checkout Order for customer purchase or settlement.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "amount": {
                            "type": "NUMBER",
                            "description": "Order total amount.",
                        },
                        "currency": {
                            "type": "STRING",
                            "description": "3-letter ISO-4217 currency code, e.g. USD.",
                        },
                        "description": {
                            "type": "STRING",
                            "description": "Order item or service description.",
                        },
                    },
                    "required": ["amount", "currency"],
                },
            },
            {
                "name": "paypal_refund_capture",
                "description": "Refund a previously captured PayPal Sandbox transaction ID.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "capture_id": {
                            "type": "STRING",
                            "description": "PayPal capture ID to refund.",
                        },
                        "amount": {
                            "type": "NUMBER",
                            "description": "Refund amount.",
                        },
                        "currency": {
                            "type": "STRING",
                            "description": "3-letter ISO-4217 currency code, e.g. USD.",
                        },
                        "note": {
                            "type": "STRING",
                            "description": "Reason for refund.",
                        },
                    },
                    "required": ["capture_id", "amount", "currency"],
                },
            },
        ]
    }
]


class GeminiAgentError(Exception):
    """Raised when Gemini API credentials are missing or the API returns an error."""


def build_kya_headers(agent_id: str, raw_body: bytes, secret: str) -> Dict[str, str]:
    """Matches Go gateway's verifyAgentAuth HMAC-SHA256 canonical digest exact format."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = uuid.uuid4().hex
    body_hash = hashlib.sha256(raw_body).hexdigest()
    canonical = f"{agent_id}|{ts}|{nonce}|{body_hash}"
    sig = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Sentinel-Agent-ID": agent_id,
        "X-Sentinel-Timestamp": ts,
        "X-Sentinel-Nonce": nonce,
        "X-Sentinel-Signature": sig,
    }


def build_ap2_intent_headers(
    secret: str,
    authorizer_id: str,
    action: str,
    max_amount: float,
    currency: str,
    recipient: str,
    ttl_seconds: int = 300,
) -> Dict[str, str]:
    """Matches Go gateway's ComputeIntentCommitment format byte-for-byte."""
    mandate_id = f"ap2-{uuid.uuid4().hex[:16]}"
    expires_unix = int(time.time()) + ttl_seconds
    clean_authorizer = (authorizer_id or "usr_demo").strip()
    clean_action = (action or "").strip().upper()
    clean_currency = (currency or "USD").strip().upper()
    clean_recipient = (recipient or "").strip()

    canonical = f"{clean_authorizer}|{clean_action}|{float(max_amount):.2f}|{clean_currency}|{clean_recipient}|{mandate_id}|{expires_unix}"
    commitment = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    headers = {
        "X-Sentinel-Intent-Authorizer": clean_authorizer,
        "X-Sentinel-Intent-Action": clean_action,
        "X-Sentinel-Intent-Max-Amount": f"{float(max_amount):.2f}",
        "X-Sentinel-Intent-Currency": clean_currency,
        "X-Sentinel-Intent-Mandate-ID": mandate_id,
        "X-Sentinel-Intent-Expires": str(expires_unix),
        "X-Sentinel-Intent-Commitment": commitment,
    }
    if clean_recipient:
        headers["X-Sentinel-Intent-Recipient"] = clean_recipient
    return headers


def invoke_gemini_tool_planner(
    prompt: str,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    timeout: float = 20.0,
) -> Dict[str, Any]:
    """
    Calls Google Gemini REST `generateContent` with PayPal Sandbox function declarations
    and extracts any structured tool call proposed by the model.
    """
    key = (api_key if api_key is not None else os.getenv("GEMINI_API_KEY", "") or os.getenv("GOOGLE_API_KEY", "")).strip()
    if not key:
        raise GeminiAgentError(
            "GEMINI_API_KEY is not configured. Add GEMINI_API_KEY to your .env or request payload."
        )

    chosen_model = (model or os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)).strip() or DEFAULT_GEMINI_MODEL
    url = f"{GEMINI_BASE_URL}/models/{chosen_model}:generateContent"

    system_prompt = (
        "You are an autonomous commerce and treasury operations agent operating under the SENTINEL "
        "Zero-Trust security gateway. Translate the user's instruction accurately into one of the "
        "available PayPal Sandbox tool calls (`paypal_payout`, `paypal_create_order`, or `paypal_refund_capture`). "
        "Preserve exact amounts, currencies, emails, notes, and IDs stated in the request so SENTINEL can audit them."
    )

    body = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "tools": GEMINI_PAYPAL_TOOLS,
        "toolConfig": {"functionCallingConfig": {"mode": "AUTO"}},
    }

    resp = requests.post(
        url,
        headers={
            "x-goog-api-key": key,
            "Content-Type": "application/json",
        },
        json=body,
        timeout=timeout,
    )
    if resp.status_code != 200:
        try:
            err_detail = resp.json()
        except Exception:
            err_detail = resp.text
        raise GeminiAgentError(f"Gemini API returned HTTP {resp.status_code}: {err_detail}")

    data = resp.json()
    candidates = data.get("candidates") or []
    parts = []
    if candidates and isinstance(candidates[0], dict):
        parts = candidates[0].get("content", {}).get("parts", []) or []

    tool_call = None
    text_parts = []
    for part in parts:
        if not isinstance(part, dict):
            continue
        if "functionCall" in part and tool_call is None:
            fc = part["functionCall"]
            tool_call = {
                "name": fc.get("name"),
                "args": fc.get("args") or {},
            }
        elif "text" in part and part["text"]:
            text_parts.append(part["text"])

    return {
        "model": chosen_model,
        "tool_call": tool_call,
        "text": "\n".join(text_parts).strip(),
    }


def enforce_via_sentinel_gateway(
    agent_id: str,
    action: str,
    payload: Dict[str, Any],
    gateway_url: Optional[str] = None,
    agent_secret: Optional[str] = None,
    intent_mandate: Optional[Dict[str, Any]] = None,
    intent_secret: Optional[str] = None,
    data_origin: Optional[str] = None,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """
    Submits the proposed tool call to SENTINEL's Go Edge Gateway (`/enforce`).
    Fails closed on network errors or non-200 HTTP responses.
    """
    target_url = (gateway_url or os.getenv("SENTINEL_GATEWAY_URL", "http://localhost:8080/enforce")).strip()
    hmac_secret = (agent_secret or os.getenv("SENTINEL_AGENT_SECRET", "sentinel-agent-auth-secret-2026")).strip()
    ap2_secret = (intent_secret or os.getenv("SENTINEL_INTENT_SECRET", "sentinel-intent-mandate-secret-2026")).strip()

    req_body = {
        "agent_id": agent_id,
        "action": action,
        "payload": payload,
    }
    raw_bytes = json.dumps(req_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = build_kya_headers(agent_id, raw_bytes, hmac_secret)

    if data_origin:
        headers["X-Sentinel-Data-Origin"] = data_origin

    if intent_mandate and intent_mandate.get("max_amount") is not None:
        headers.update(
            build_ap2_intent_headers(
                secret=ap2_secret,
                authorizer_id=str(intent_mandate.get("authorizer_id", "usr_operator")),
                action=str(intent_mandate.get("authorized_action") or action),
                max_amount=float(intent_mandate["max_amount"]),
                currency=str(intent_mandate.get("currency") or payload.get("currency") or "USD"),
                recipient=str(intent_mandate.get("recipient") or ""),
            )
        )

    try:
        resp = requests.post(target_url, data=raw_bytes, headers=headers, timeout=timeout)
    except Exception as exc:
        return {
            "decision": "DENY",
            "status_code": 503,
            "error": "GATEWAY_UNREACHABLE",
            "message": f"Fail-closed: SENTINEL Edge Gateway unreachable ({exc})",
            "wal_seq": None,
            "wal_hash": None,
        }

    try:
        resp_json = resp.json()
    except Exception:
        resp_json = {"status": "DENY" if resp.status_code != 200 else "ALLOW", "message": resp.text}

    decision = str(resp_json.get("status", "DENY")).upper()
    if resp.status_code != 200 or decision != "ALLOW":
        return {
            "decision": "DENY",
            "status_code": resp.status_code,
            "error": resp_json.get("error", f"HTTP_{resp.status_code}"),
            "message": resp_json.get("message", "Blocked by SENTINEL Edge Gateway"),
            "wal_seq": resp.headers.get("X-Sentinel-WAL-Seq"),
            "wal_hash": resp.headers.get("X-Sentinel-WAL-Hash"),
        }

    return {
        "decision": "ALLOW",
        "status_code": resp.status_code,
        "error": None,
        "message": resp_json.get("message", "Transaction permitted."),
        "wal_seq": resp.headers.get("X-Sentinel-WAL-Seq"),
        "wal_hash": resp.headers.get("X-Sentinel-WAL-Hash"),
    }


def _execute_paypal_action(
    client: PayPalSandboxClient,
    action: str,
    payload: Dict[str, Any],
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    if action == "PAYPAL_PAYOUT":
        recipient = str(payload.get("recipient_email") or payload.get("recipient") or os.getenv("PAYPAL_DEFAULT_RECEIVER", "sb-buyer@personal.example.com"))
        return client.create_payout(
            recipient_email=recipient,
            amount=float(payload["amount"]),
            currency=str(payload.get("currency", "USD")),
            note=str(payload.get("note", "SENTINEL verified Gemini AI payout")),
            request_id=request_id,
        )
    if action == "PAYPAL_CREATE_ORDER":
        return client.create_order(
            amount=float(payload["amount"]),
            currency=str(payload.get("currency", "USD")),
            description=str(payload.get("description") or payload.get("note") or "SENTINEL verified Gemini AI order"),
            request_id=request_id,
        )
    if action == "PAYPAL_REFUND":
        return client.refund_capture(
            capture_id=str(payload.get("capture_id", "")),
            amount=float(payload["amount"]) if payload.get("amount") is not None else None,
            currency=str(payload.get("currency", "USD")),
            note=str(payload.get("note", "SENTINEL verified Gemini refund")),
            request_id=request_id,
        )
    raise PayPalSandboxError(f"Unsupported PayPal action: {action}")


def run_guarded_paypal_agent(
    prompt: str,
    agent_id: str = "ag_Travel_Bot",
    mandate_max_amount: Optional[float] = None,
    mandate_currency: str = "USD",
    mandate_recipient: Optional[str] = None,
    mandate_authorized_action: Optional[str] = None,
    data_origin: Optional[str] = None,
    gemini_api_key: Optional[str] = None,
    gemini_model: Optional[str] = None,
    paypal_client_id: Optional[str] = None,
    paypal_client_secret: Optional[str] = None,
    gateway_url: Optional[str] = None,
    direct_tool_override: Optional[Tuple[str, Dict[str, Any]]] = None,
    dry_run_paypal: bool = False,
    log_recorder: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """
    Runs the complete end-to-end flow:
      Gemini Tool Planning -> SENTINEL Zero-Trust Gate -> PayPal Developer Sandbox
    """
    # 1. Plan tool call via Google Gemini (unless running an explicit raw red-team payload replay)
    if direct_tool_override is not None:
        action, payload = direct_tool_override
        gemini_result = {
            "mode": "direct_adversarial_probe",
            "model": gemini_model or os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL),
            "tool_call": {"name": action, "args": payload},
            "text": "Bypassed LLM planning to probe raw tool call against SENTINEL edge.",
        }
        tool_name = action
        tool_args = dict(payload)
    else:
        gemini_result = invoke_gemini_tool_planner(
            prompt=prompt,
            api_key=gemini_api_key,
            model=gemini_model,
        )
        tc = gemini_result.get("tool_call")
        if not tc:
            return {
                "status": "NO_TOOL_CALL",
                "decision": "DENY",
                "gemini": gemini_result,
                "sentinel": {
                    "decision": "SKIPPED",
                    "message": "Gemini did not propose a PayPal tool execution for this prompt.",
                },
                "paypal": {
                    "executed": False,
                    "status": "SKIPPED_NO_TOOL_CALL",
                },
            }
        tool_name = str(tc.get("name", ""))
        tool_args = dict(tc.get("args") or {})
        action = TOOL_TO_SENTINEL_ACTION.get(tool_name, tool_name.upper())

    payload_for_gateway: Dict[str, Any] = dict(tool_args)
    if "time" not in payload_for_gateway:
        payload_for_gateway["time"] = datetime.now().strftime("%H:%M:%S")

    # 2. Enforce via SENTINEL Edge Gateway
    intent_mandate = None
    if mandate_max_amount is not None:
        intent_mandate = {
            "authorizer_id": "usr_dashboard_operator",
            "authorized_action": mandate_authorized_action or action,
            "max_amount": float(mandate_max_amount),
            "currency": mandate_currency,
            "recipient": mandate_recipient or "",
        }

    sentinel_verdict = enforce_via_sentinel_gateway(
        agent_id=agent_id,
        action=action,
        payload=payload_for_gateway,
        gateway_url=gateway_url,
        intent_mandate=intent_mandate,
        data_origin=data_origin,
    )

    # 3. Gate PayPal Sandbox Execution
    if sentinel_verdict["decision"] != "ALLOW":
        paypal_result: Dict[str, Any] = {
            "executed": False,
            "environment": "sandbox",
            "status": "BLOCKED_BEFORE_PAYPAL",
            "reason": sentinel_verdict.get("message"),
        }
        final_status = "BLOCKED"
    elif dry_run_paypal:
        paypal_result = {
            "executed": False,
            "environment": "sandbox",
            "status": "DRY_RUN_ALLOWED",
            "operation": action,
            "message": "SENTINEL approved action; dry_run_paypal=True skipped external PayPal HTTP call.",
        }
        final_status = "ALLOW"
    else:
        pp_client = PayPalSandboxClient(
            client_id=paypal_client_id,
            client_secret=paypal_client_secret,
        )
        if not pp_client.is_configured():
            paypal_result = {
                "executed": False,
                "environment": "sandbox",
                "status": "PAYPAL_CREDENTIALS_MISSING",
                "message": "SENTINEL returned ALLOW, but PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET are not configured.",
            }
            final_status = "ALLOWED_UNCONFIGURED_PAYPAL"
        else:
            try:
                wal_seq = sentinel_verdict.get("wal_seq")
                req_id = f"sentinel-wal-{wal_seq}" if wal_seq else None
                paypal_result = _execute_paypal_action(pp_client, action, payload_for_gateway, request_id=req_id)
                final_status = "EXECUTED_IN_PAYPAL_SANDBOX"
            except PayPalSandboxError as exc:
                paypal_result = {
                    "executed": False,
                    "environment": "sandbox",
                    "status": "PAYPAL_API_ERROR",
                    "error": str(exc),
                    "status_code": exc.status_code,
                    "details": exc.details,
                }
                final_status = "ALLOWED_PAYPAL_ERROR"

    if log_recorder is not None:
        log_recorder(
            {
                "agent": agent_id,
                "action": action,
                "payload": payload_for_gateway,
                "decision": sentinel_verdict["decision"],
                "wal_hash": sentinel_verdict.get("wal_hash"),
                "prompt": prompt,
                "message": sentinel_verdict.get("message") or paypal_result.get("message") or "",
                "paypal_id": (
                    paypal_result.get("payout_batch_id")
                    or paypal_result.get("order_id")
                    or paypal_result.get("refund_id")
                ),
            }
        )

    return {
        "status": final_status,
        "decision": sentinel_verdict["decision"],
        "gemini": {
            "model": gemini_result.get("model"),
            "tool_name": tool_name,
            "sentinel_action": action,
            "arguments": payload_for_gateway,
            "text": gemini_result.get("text", ""),
        },
        "sentinel": sentinel_verdict,
        "paypal": paypal_result,
    }
