"""
SENTINEL PayPal Developer Sandbox Connector.

Executes real PayPal Sandbox REST API operations (OAuth 2.0 client_credentials,
Payouts v1, Orders v2, and Capture Refunds v2) ONLY after SENTINEL's zero-trust
edge gateway and behavioral Case Law policy return ALLOW.
"""

import base64
import logging
import os
import threading
import time
import uuid
from typing import Any, Dict, Optional

import requests

SANDBOX_BASE_URL = "https://api-m.sandbox.paypal.com"

ZERO_DECIMAL_CURRENCIES = {"JPY", "HUF", "TWD"}
THREE_DECIMAL_CURRENCIES = {"KWD", "BHD", "OMR", "JOD", "TND"}


class PayPalSandboxError(Exception):
    """Raised when PayPal Sandbox credentials are missing or an API call fails."""

    def __init__(self, message: str, status_code: Optional[int] = None, details: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details


def format_paypal_amount(amount: float, currency: str = "USD") -> str:
    """Formats numeric currency amounts according to ISO-4217 rules expected by PayPal."""
    curr = (currency or "USD").strip().upper()
    val = float(amount)
    if curr in ZERO_DECIMAL_CURRENCIES:
        return f"{int(round(val))}"
    if curr in THREE_DECIMAL_CURRENCIES:
        return f"{val:.3f}"
    return f"{val:.2f}"


class PayPalSandboxClient:
    """Thread-safe PayPal Developer Sandbox REST API v1/v2 client."""

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        mode: Optional[str] = None,
        timeout: float = 15.0,
    ):
        self.client_id = (client_id if client_id is not None else os.getenv("PAYPAL_CLIENT_ID", "")).strip()
        self.client_secret = (client_secret if client_secret is not None else os.getenv("PAYPAL_CLIENT_SECRET", "")).strip()
        self.mode = (mode if mode is not None else os.getenv("PAYPAL_MODE", "sandbox")).strip().lower()
        if self.mode != "sandbox":
            raise PayPalSandboxError(
                f"Unsafe PAYPAL_MODE='{self.mode}'. SENTINEL PayPal connector strictly permits 'sandbox' mode."
            )
        self.base_url = SANDBOX_BASE_URL
        self.timeout = timeout
        self._lock = threading.Lock()
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0

    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def _require_configured(self) -> None:
        if not self.is_configured():
            raise PayPalSandboxError(
                "PayPal Sandbox credentials missing. Set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET in .env."
            )

    def get_access_token(self, force_refresh: bool = False) -> str:
        """Exchanges Sandbox Client ID/Secret for an OAuth 2.0 Bearer access token."""
        self._require_configured()
        now = time.time()
        with self._lock:
            if not force_refresh and self._access_token and now < self._token_expires_at - 60:
                return self._access_token

            basic_creds = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode("utf-8")).decode("ascii")
            resp = requests.post(
                f"{self.base_url}/v1/oauth2/token",
                headers={
                    "Authorization": f"Basic {basic_creds}",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
                data={"grant_type": "client_credentials"},
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                raise PayPalSandboxError(
                    f"PayPal Sandbox OAuth2 failed (HTTP {resp.status_code})",
                    status_code=resp.status_code,
                    details=_safe_json(resp),
                )
            payload = resp.json()
            token = payload.get("access_token")
            expires_in = int(payload.get("expires_in", 3600))
            if not token:
                raise PayPalSandboxError("PayPal OAuth2 response missing access_token", details=payload)
            self._access_token = token
            self._token_expires_at = now + expires_in
            return token

    def verify_connection(self) -> Dict[str, Any]:
        """Performs a live OAuth2 check against PayPal Developer Sandbox."""
        if not self.is_configured():
            return {
                "configured": False,
                "connected": False,
                "environment": "sandbox",
                "base_url": self.base_url,
                "message": "PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET not configured.",
            }
        try:
            self.get_access_token(force_refresh=True)
            return {
                "configured": True,
                "connected": True,
                "environment": "sandbox",
                "base_url": self.base_url,
                "message": "Authenticated successfully with PayPal Developer Sandbox OAuth2.",
            }
        except PayPalSandboxError as e:
            return {
                "configured": True,
                "connected": False,
                "environment": "sandbox",
                "base_url": self.base_url,
                "message": str(e),
                "details": e.details,
            }

    def create_payout(
        self,
        recipient_email: str,
        amount: float,
        currency: str = "USD",
        note: str = "SENTINEL verified AI payout",
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Disburses a real PayPal Sandbox Payout (`POST /v1/payments/payouts`)."""
        token = self.get_access_token()
        req_id = request_id or f"sentinel-payout-{uuid.uuid4().hex[:16]}"
        curr = (currency or "USD").strip().upper()
        formatted_value = format_paypal_amount(amount, curr)
        body = {
            "sender_batch_header": {
                "sender_batch_id": f"SENTINEL_{uuid.uuid4().hex[:12]}",
                "email_subject": "You have a SENTINEL-verified PayPal Sandbox payout",
                "email_message": note or "Authorized via SENTINEL Zero-Trust AI Gateway.",
            },
            "items": [
                {
                    "recipient_type": "EMAIL",
                    "amount": {"value": formatted_value, "currency": curr},
                    "receiver": recipient_email.strip(),
                    "note": note or "Authorized via SENTINEL",
                    "sender_item_id": f"item_{uuid.uuid4().hex[:10]}",
                }
            ],
        }
        resp = requests.post(
            f"{self.base_url}/v1/payments/payouts",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "PayPal-Request-Id": req_id,
            },
            json=body,
            timeout=self.timeout,
        )
        data = _safe_json(resp)
        if resp.status_code not in (200, 201):
            raise PayPalSandboxError(
                f"PayPal Payouts API returned HTTP {resp.status_code}",
                status_code=resp.status_code,
                details=data,
            )
        batch_header = data.get("batch_header", {}) if isinstance(data, dict) else {}
        return {
            "executed": True,
            "environment": "sandbox",
            "operation": "PAYPAL_PAYOUT",
            "payout_batch_id": batch_header.get("payout_batch_id"),
            "batch_status": batch_header.get("batch_status"),
            "amount": formatted_value,
            "currency": curr,
            "recipient_email": recipient_email.strip(),
            "paypal_request_id": req_id,
            "paypal_debug_id": resp.headers.get("PayPal-Debug-Id"),
            "raw": data,
        }

    def create_order(
        self,
        amount: float,
        currency: str = "USD",
        description: str = "SENTINEL verified AI order",
        reference_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Creates a real PayPal Sandbox Checkout Order (`POST /v2/checkout/orders`)."""
        token = self.get_access_token()
        req_id = request_id or f"sentinel-order-{uuid.uuid4().hex[:16]}"
        curr = (currency or "USD").strip().upper()
        formatted_value = format_paypal_amount(amount, curr)
        body = {
            "intent": "CAPTURE",
            "purchase_units": [
                {
                    "reference_id": reference_id or f"SENTINEL-{uuid.uuid4().hex[:8]}",
                    "description": description or "SENTINEL Zero-Trust Verified Order",
                    "amount": {"currency_code": curr, "value": formatted_value},
                }
            ],
        }
        resp = requests.post(
            f"{self.base_url}/v2/checkout/orders",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "PayPal-Request-Id": req_id,
            },
            json=body,
            timeout=self.timeout,
        )
        data = _safe_json(resp)
        if resp.status_code not in (200, 201):
            raise PayPalSandboxError(
                f"PayPal Orders API v2 returned HTTP {resp.status_code}",
                status_code=resp.status_code,
                details=data,
            )
        approve_url = None
        if isinstance(data, dict):
            for link in data.get("links", []):
                if isinstance(link, dict) and link.get("rel") == "approve":
                    approve_url = link.get("href")
                    break
        return {
            "executed": True,
            "environment": "sandbox",
            "operation": "PAYPAL_CREATE_ORDER",
            "order_id": data.get("id") if isinstance(data, dict) else None,
            "status": data.get("status") if isinstance(data, dict) else None,
            "approve_url": approve_url,
            "amount": formatted_value,
            "currency": curr,
            "paypal_request_id": req_id,
            "paypal_debug_id": resp.headers.get("PayPal-Debug-Id"),
            "raw": data,
        }

    def refund_capture(
        self,
        capture_id: str,
        amount: Optional[float] = None,
        currency: str = "USD",
        note: str = "SENTINEL verified refund",
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Issues a real PayPal Sandbox refund (`POST /v2/payments/captures/{capture_id}/refund`)."""
        clean_capture = (capture_id or "").strip()
        if not clean_capture:
            raise PayPalSandboxError("capture_id is required for PAYPAL_REFUND")
        token = self.get_access_token()
        req_id = request_id or f"sentinel-refund-{uuid.uuid4().hex[:16]}"
        curr = (currency or "USD").strip().upper()
        body: Dict[str, Any] = {}
        if note:
            body["note_to_payer"] = note[:255]
        formatted_value = None
        if amount is not None:
            formatted_value = format_paypal_amount(amount, curr)
            body["amount"] = {"value": formatted_value, "currency_code": curr}

        resp = requests.post(
            f"{self.base_url}/v2/payments/captures/{clean_capture}/refund",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "PayPal-Request-Id": req_id,
            },
            json=body,
            timeout=self.timeout,
        )
        data = _safe_json(resp)
        if resp.status_code not in (200, 201):
            raise PayPalSandboxError(
                f"PayPal Refunds API v2 returned HTTP {resp.status_code}",
                status_code=resp.status_code,
                details=data,
            )
        return {
            "executed": True,
            "environment": "sandbox",
            "operation": "PAYPAL_REFUND",
            "refund_id": data.get("id") if isinstance(data, dict) else None,
            "capture_id": clean_capture,
            "status": data.get("status") if isinstance(data, dict) else None,
            "amount": formatted_value,
            "currency": curr,
            "paypal_request_id": req_id,
            "paypal_debug_id": resp.headers.get("PayPal-Debug-Id"),
            "raw": data,
        }


def _safe_json(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        logging.debug("Non-JSON response from PayPal (%s)", resp.status_code)
        return resp.text

