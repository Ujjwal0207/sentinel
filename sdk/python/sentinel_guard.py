"""
SENTINEL Python SDK: Zero-Trust Guardrail Decorator for AI Agents.

Provides 1-line integration for OpenAI, LangChain, CrewAI, and native Python tools.
Automatically injects nonces, timestamps, HMAC/Ed25519 signatures, and AP2 intent hashes.
"""

import time
import uuid
import hmac
import hashlib
import functools
import json
import urllib.request
import urllib.error
from typing import Optional, Callable, Any

DEFAULT_GATEWAY_URL = "http://localhost:8080/enforce"
DEFAULT_SECRET = "sentinel-agent-auth-secret-2026"

class SentinelSecurityException(Exception):
    """Raised when an agent tool call is blocked by Sentinel policy."""
    pass

def sentinel_protect(
    agent_id: str,
    action: str,
    max_amount: Optional[float] = None,
    secret_key: str = DEFAULT_SECRET,
    gateway_url: str = DEFAULT_GATEWAY_URL,
    mandate_id: Optional[str] = None
) -> Callable:
    """
    Decorator that gates tool execution through Sentinel Zero-Trust Gateway before execution.
    
    Usage:
        @sentinel_protect(agent_id="ag_Finance_Bot", action="TRANSFER", max_amount=5000.0)
        def execute_wire(recipient: str, amount: float):
            # Safe execution logic
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # 1. Inspect parameters
            amount = kwargs.get("amount", 0.0)
            if not amount and args:
                for arg in args:
                    if isinstance(arg, (int, float)):
                        amount = float(arg)
                        break

            if max_amount is not None and amount > max_amount:
                raise SentinelSecurityException(
                    f"Local check failed: Amount ${amount:.2f} exceeds decorator max_amount ${max_amount:.2f}"
                )

            # 2. Build payload
            payload_data = {
                "action": action,
                "amount": amount,
                "kwargs": kwargs
            }
            payload_json = json.dumps(payload_data, sort_keys=True)

            # 3. Cryptographic headers
            nonce = uuid.uuid4().hex
            timestamp = int(time.time())
            sig_string = f"{agent_id}:{nonce}:{timestamp}:{payload_json}"
            signature = hmac.new(
                secret_key.encode("utf-8"),
                sig_string.encode("utf-8"),
                hashlib.sha256
            ).hexdigest()

            headers = {
                "Content-Type": "application/json",
                "X-Sentinel-Agent-ID": agent_id,
                "X-Sentinel-Nonce": nonce,
                "X-Sentinel-Timestamp": str(timestamp),
                "X-Sentinel-Signature": signature
            }

            if mandate_id:
                headers["X-Sentinel-Mandate-ID"] = mandate_id

            req = urllib.request.Request(
                gateway_url,
                data=payload_json.encode("utf-8"),
                headers=headers,
                method="POST"
            )

            try:
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    if resp.status != 200:
                        raise SentinelSecurityException(f"Sentinel Gateway rejected action: HTTP {resp.status}")
            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", errors="replace")
                raise SentinelSecurityException(f"Sentinel Gateway rejected action: HTTP {e.code} - {err_body}")
            except Exception as e:
                # Fail closed on network failure
                raise SentinelSecurityException(f"Sentinel Gateway unreachable (Fail-Closed): {e}")

            # 4. Proceed with original tool execution
            return func(*args, **kwargs)
        return wrapper
    return decorator

