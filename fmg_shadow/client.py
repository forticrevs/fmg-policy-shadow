"""
FortiManager JSON-RPC client.

Uses only Python stdlib (urllib, json, ssl) for zero-dependency operation.
Supports session-based (user/passwd) and API-token authentication.
"""

from __future__ import annotations

import json
import logging
import ssl
import threading
import time
import urllib.request
import urllib.error
from typing import Any, Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class FMGError(Exception):
    """Base exception for FMG client errors."""

    def __init__(self, message: str, code: int = -1, url: str = ""):
        self.code = code
        self.url = url
        super().__init__(message)


class FMGAuthError(FMGError):
    """Authentication / session error."""


class FMGRequestError(FMGError):
    """Non-retryable request error from FMG."""


# ---------------------------------------------------------------------------
# Status codes
# ---------------------------------------------------------------------------

# 0  = success
# -6 = invalid URL (acceptable in some bulk queries)
_OK_CODES = frozenset((0, -6))


# ---------------------------------------------------------------------------
# FMGClient
# ---------------------------------------------------------------------------

class FMGClient:
    """FortiManager JSON-RPC client.

    Usage (session auth)::

        with FMGClient("fmg.example.com", username="admin", password="pw") as fmg:
            pkgs = fmg.get("/pm/pkg/adom/root")
            ...

    Usage (API token)::

        fmg = FMGClient("fmg.example.com", token="my-api-token")
        pkgs = fmg.get("/pm/pkg/adom/root")
    """

    # Retry defaults
    MAX_RETRIES = 3
    BACKOFF_BASE = 1.0  # seconds; doubles each retry

    def __init__(
        self,
        host: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        token: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: int = 60,
    ) -> None:
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        self._url = f"https://{self.host}/jsonrpc"
        self._session: Optional[str] = None

        # Thread-safe request ID counter
        self._id_lock = threading.Lock()
        self._id_counter = 0

        # SSL context
        self._ssl_ctx = self._make_ssl_context()

    # -- helpers ------------------------------------------------------------

    def _make_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _next_id(self) -> int:
        with self._id_lock:
            self._id_counter += 1
            return self._id_counter

    # -- low-level HTTP -----------------------------------------------------

    def _post(self, payload: Any, timeout: Optional[int] = None) -> Any:
        """POST *payload* (already a Python object) and return parsed JSON."""
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self._url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        # API-token auth uses Bearer header
        if self.token and not self._session:
            req.add_header("Authorization", f"Bearer {self.token}")

        effective_timeout = timeout or self.timeout
        log.debug("POST %s  payload=%s", self._url, payload)

        resp = urllib.request.urlopen(
            req, timeout=effective_timeout, context=self._ssl_ctx
        )
        raw = resp.read()
        result = json.loads(raw)
        log.debug("Response: %s", result)
        return result

    # -- authentication -----------------------------------------------------

    def login(self) -> None:
        """Authenticate with username/password and store session token."""
        if self.token:
            # Token auth doesn't need login
            log.debug("Using API-token auth; skipping login.")
            return
        if not self.username:
            raise FMGAuthError("No username or token provided for authentication")

        payload = {
            "id": self._next_id(),
            "method": "exec",
            "params": [
                {
                    "url": "/sys/login/user",
                    "data": {
                        "user": self.username,
                        "passwd": self.password or "",
                    },
                }
            ],
            "verbose": 1,
        }

        resp = self._post(payload)
        self._session = resp.get("session")
        if not self._session:
            raise FMGAuthError(
                "Login failed – no session token in response. "
                f"Response: {resp}"
            )
        log.info("Logged in to %s (session=%s...)", self.host, self._session[:8])

    def logout(self) -> None:
        """End the current session."""
        if not self._session:
            return
        try:
            payload = {
                "id": self._next_id(),
                "method": "exec",
                "params": [{"url": "/sys/logout"}],
                "session": self._session,
                "verbose": 1,
            }
            self._post(payload)
            log.info("Logged out from %s", self.host)
        except Exception as exc:
            log.warning("Logout error (ignored): %s", exc)
        finally:
            self._session = None

    # -- context manager ----------------------------------------------------

    def __enter__(self) -> "FMGClient":
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.logout()

    # -- core RPC -----------------------------------------------------------

    def rpc(
        self,
        method: str,
        params: list[dict[str, Any]],
        timeout: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """Execute a single JSON-RPC call with automatic retries.

        Parameters
        ----------
        method : str
            JSON-RPC method (``get``, ``set``, ``exec``, ``add``, …).
        params : list[dict]
            List of param dicts (usually one element).
        timeout : int, optional
            Per-request timeout override.

        Returns
        -------
        list[dict]
            The ``result`` list from the response.

        Raises
        ------
        FMGError
            On non-OK status codes after exhausting retries.
        """
        payload: dict[str, Any] = {
            "id": self._next_id(),
            "method": method,
            "params": params,
            "verbose": 1,
        }
        if self._session:
            payload["session"] = self._session

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                resp = self._post(payload, timeout=timeout)
                return self._check_response(resp)
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                last_exc = exc
                if attempt < self.MAX_RETRIES:
                    wait = self.BACKOFF_BASE * (2 ** (attempt - 1))
                    log.warning(
                        "RPC attempt %d/%d failed (%s), retrying in %.1fs …",
                        attempt,
                        self.MAX_RETRIES,
                        exc,
                        wait,
                    )
                    time.sleep(wait)
            except FMGError:
                raise  # don't retry application-level errors

        raise FMGError(f"RPC failed after {self.MAX_RETRIES} attempts: {last_exc}")

    # -- batch RPC ----------------------------------------------------------

    def rpc_batch(
        self,
        requests: list[dict[str, Any]],
        timeout: Optional[int] = None,
    ) -> list[list[dict[str, Any]]]:
        """Send multiple JSON-RPC objects in a single HTTP POST (JSON array).

        Each element in *requests* should be a dict with ``method`` and
        ``params`` keys.  This method wraps them into a JSON array and sends
        them as one POST.  Returns a list of result lists, one per request.

        Parameters
        ----------
        requests : list[dict]
            Each dict must have ``method`` (str) and ``params`` (list[dict]).
        timeout : int, optional
            Per-request timeout override.

        Returns
        -------
        list[list[dict]]
            List of result arrays, one per request in the batch.
        """
        payload = []
        for req in requests:
            obj: dict[str, Any] = {
                "id": self._next_id(),
                "method": req["method"],
                "params": req["params"],
                "verbose": 1,
            }
            if self._session:
                obj["session"] = self._session
            payload.append(obj)

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                resp = self._post(payload, timeout=timeout)
                # resp should be a list of response objects
                if not isinstance(resp, list):
                    resp = [resp]
                return [self._check_response(r) for r in resp]
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                last_exc = exc
                if attempt < self.MAX_RETRIES:
                    wait = self.BACKOFF_BASE * (2 ** (attempt - 1))
                    log.warning(
                        "Batch RPC attempt %d/%d failed (%s), retrying in %.1fs …",
                        attempt,
                        self.MAX_RETRIES,
                        exc,
                        wait,
                    )
                    time.sleep(wait)
            except FMGError:
                raise

        raise FMGError(
            f"Batch RPC failed after {self.MAX_RETRIES} attempts: {last_exc}"
        )

    # -- convenience GET wrapper --------------------------------------------

    def get(
        self,
        url: str,
        fields: Optional[list[str]] = None,
        filter: Optional[list] = None,
        option: Optional[list[str] | str] = None,
        range_: Optional[list[int]] = None,
        loadsub: Optional[int] = None,
        expand_datasrc: Optional[list[dict[str, str]]] = None,
        get_referred: Optional[list[dict[str, str]]] = None,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """High-level GET helper.

        Parameters
        ----------
        url : str
            FMG object URL, e.g. ``/pm/config/adom/root/pkg/…``.
        fields : list[str], optional
            Restrict returned fields.
        filter : list, optional
            FMG filter expression (list of lists).
        option : str or list[str], optional
            Extra option flags (e.g. ``"object member"``).
        range_ : list[int], optional
            ``[start, count]`` for pagination.
        loadsub : int, optional
            Forwarded as the raw FMG ``loadsub`` request parameter.
        expand_datasrc : list[dict], optional
            Datasource expansion list (added as ``"expand datasrc"``).
        get_referred : list[dict], optional
            Referred object expansion (FMG 7.4.3+, added as ``"get referred"``).

        Returns
        -------
        list[dict]
            The ``data`` portion from the first result entry.
        """
        if "range" in kwargs and range_ is None:
            range_ = kwargs.pop("range")
        if kwargs:
            unexpected = ", ".join(sorted(kwargs.keys()))
            raise TypeError(f"FMGClient.get() got unexpected keyword argument(s): {unexpected}")

        param: dict[str, Any] = {"url": url}
        if fields is not None:
            param["fields"] = fields
        if filter is not None:
            param["filter"] = filter
        if option is not None:
            param["option"] = option
        if range_ is not None:
            param["range"] = range_
        if loadsub is not None:
            param["loadsub"] = loadsub
        if expand_datasrc is not None:
            param["expand datasrc"] = expand_datasrc
        if get_referred is not None:
            param["get referred"] = get_referred

        results = self.rpc("get", [param])
        # Return data from first result element
        if results and isinstance(results, list):
            first = results[0]
            if isinstance(first, dict):
                return first.get("data", first)
        return results

    # -- response validation ------------------------------------------------

    @staticmethod
    def _check_response(resp: dict[str, Any]) -> list[dict[str, Any]]:
        """Validate a single JSON-RPC response and return its result list.

        Raises :class:`FMGError` when the response status code indicates
        failure (anything other than 0 or -6).
        """
        results = resp.get("result", [])
        if not isinstance(results, list):
            results = [results]

        for entry in results:
            if not isinstance(entry, dict):
                continue
            status = entry.get("status", {})
            code = status.get("code", 0)
            if code not in _OK_CODES:
                msg = status.get("message", "unknown error")
                entry_url = entry.get("url", "")
                raise FMGError(
                    f"FMG error {code}: {msg} (url={entry_url})",
                    code=code,
                    url=entry_url,
                )
        return results
