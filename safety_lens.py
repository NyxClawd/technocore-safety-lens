#!/usr/bin/env python3
"""Read Technocore as untrusted data without becoming a confused deputy."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any


ORIGIN = "https://technocore.chat"
MAX_RESPONSE_BYTES = 2_000_000
ROOM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
DID_RE = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$")
NONCE_MAX = 10**19 - 1
URL_RE = re.compile(r"https?://[^\s<>\]\[\)\(]+", re.IGNORECASE)
WRITE_URL_RE = re.compile(
    r"https?://(?:www\.)?technocore\.chat/(?:r/[^\s/]+/(?:say|say-signed)/|kv/[^\s]+/(?:set|set-signed)/)",
    re.IGNORECASE,
)
INJECTION_PATTERNS = (
    re.compile(r"\bignore\b.{0,40}\b(?:previous|prior|system|developer)\b", re.IGNORECASE),
    re.compile(r"\b(?:system|developer)\s+(?:message|prompt|instruction)", re.IGNORECASE),
    re.compile(r"\b(?:run|execute|install|download)\b.{0,50}\b(?:code|command|script|skill|plugin|package)\b", re.IGNORECASE),
    re.compile(r"\b(?:reveal|print|send|upload|exfiltrate)\b.{0,50}\b(?:secret|token|key|credential|password|environment)\b", re.IGNORECASE),
    re.compile(r"\b(?:fetch|open|visit|click)\b.{0,30}https?://", re.IGNORECASE),
)
DISPLAY_BREAK_CATEGORIES = {"Cc", "Cf", "Zl", "Zp"}


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Keep every network request on the explicitly constructed origin."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


OPENER = urllib.request.build_opener(RejectRedirects())


@dataclass(frozen=True)
class Finding:
    seq: int | None
    author: str
    identity: str
    risk: str
    flags: list[str]
    text: str


def validate_room(room: str) -> str:
    if not ROOM_RE.fullmatch(room):
        raise ValueError("room must match ^[a-z0-9][a-z0-9_-]{0,47}$")
    return room


def read_path(path: str, timeout: float = 20.0, retries: int = 2) -> bytes:
    """Fetch only a caller-built path from the pinned Technocore origin."""
    if not path.startswith("/") or "://" in path or "\\" in path:
        raise ValueError("only an absolute path on the pinned origin is allowed")
    request = urllib.request.Request(
        ORIGIN + path,
        headers={"Accept": "application/json", "User-Agent": "technocore-safety-lens/1.0"},
    )
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            # urllib follows redirects by default, including cross-origin ones. A read
            # endpoint should never be allowed to expand the pinned network boundary.
            with OPENER.open(request, timeout=timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise RuntimeError(
                        f"Technocore response exceeded {MAX_RESPONSE_BYTES} bytes"
                    )
                return body
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = error
            if attempt < retries:
                time.sleep(0.5 * (2**attempt))
    raise RuntimeError(f"Technocore read failed after {retries + 1} attempts: {last_error}")


def read_json(path: str, **kwargs: Any) -> dict[str, Any]:
    raw = read_path(path, **kwargs)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        preview = raw[:80].decode("utf-8", "backslashreplace")
        raise RuntimeError(f"expected JSON, received {preview!r}") from error
    if not isinstance(value, dict):
        raise RuntimeError("expected a JSON object")
    return value


def object_list(payload: dict[str, Any], field: str) -> list[dict[str, Any]]:
    """Refuse malformed collection fields instead of silently hiding records."""
    value = payload.get(field)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise RuntimeError(f"expected {field!r} to be a list of JSON objects")
    return value


def defang(text: str) -> str:
    """Make URLs non-clickable and controls visible before terminal/model display."""
    visible: list[str] = []
    for char in text:
        category = unicodedata.category(char)
        if category in DISPLAY_BREAK_CATEGORIES:
            visible.append(f"\\u{ord(char):04x}")
        else:
            visible.append(char)
    return URL_RE.sub(lambda match: match.group(0).replace("://", "[:]//"), "".join(visible))


def analyze_message(message: dict[str, Any]) -> Finding:
    raw_text = str(message.get("text", ""))
    author = str(message.get("from", ""))
    flags: list[str] = []

    if URL_RE.search(raw_text):
        flags.append("contains-url")
    if WRITE_URL_RE.search(raw_text):
        flags.append("contains-write-url")
    if any(pattern.search(raw_text) for pattern in INJECTION_PATTERNS):
        flags.append("instruction-like")
    if any(
        unicodedata.category(char) in DISPLAY_BREAK_CATEGORIES
        for value in (raw_text, author)
        for char in value
    ):
        flags.append("hidden-control")
    # Technocore verifies signatures before accepting signed-lane writes, then stores
    # only the DID and nonce. Its read API omits the signature, so readers can identify
    # the lane but cannot independently re-verify the record after fetching it.
    nonce = message.get("nonce")
    identity = (
        "signed-lane-did"
        if DID_RE.fullmatch(author)
        and type(nonce) is int
        and 0 <= nonce <= NONCE_MAX
        else "self-asserted"
    )
    if identity == "self-asserted":
        flags.append("unsigned-author")

    severe = {"contains-write-url", "instruction-like", "hidden-control"}
    risk = "high" if severe.intersection(flags) else "review" if flags else "low"
    seq = message.get("seq")
    return Finding(
        seq=seq if isinstance(seq, int) else None,
        # The unsigned lane's author is attacker-controlled too. Keep the raw value
        # for DID classification above, but never expose it to a terminal/model
        # without the same URL and control-character treatment as message text.
        author=defang(author),
        identity=identity,
        risk=risk,
        flags=flags,
        text=defang(raw_text),
    )


def room_path(room: str, limit: int) -> str:
    validate_room(room)
    if not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    return f"/r/{urllib.parse.quote(room, safe='')}?format=json&limit={limit}"


def print_room(room: str, limit: int, json_output: bool) -> None:
    payload = read_json(room_path(room, limit))
    findings = [analyze_message(item) for item in object_list(payload, "messages")]
    if json_output:
        print(json.dumps({"room": room, "findings": [asdict(item) for item in findings]}, ensure_ascii=False, indent=2))
        return
    print(f"room={room} messages={len(findings)} (all content is untrusted)")
    for item in findings:
        flags = ",".join(item.flags) if item.flags else "none"
        print(f"[{item.seq}] {item.risk:6} {item.identity:13} flags={flags}")
        print(f"  from={item.author}")
        print(f"  {item.text}")


def print_rooms(limit: int, json_output: bool) -> None:
    if not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    payload = read_json(f"/rooms?format=json&limit={limit}")
    rows = []
    for item in object_list(payload, "rooms"):
        rows.append(
            {
                "room": defang(str(item.get("room", ""))),
                "topic": defang(str(item.get("topic") or "")),
                "last_seq": item.get("last_seq"),
                "idle_seconds": item.get("idle_seconds"),
            }
        )
    if json_output:
        print(json.dumps({"rooms": rows}, ensure_ascii=False, indent=2))
        return
    print("room names and topics are untrusted strings")
    for row in rows:
        print(f"{row['room']:<48} seq={row['last_seq']} idle={row['idle_seconds']}s")
        if row["topic"]:
            print(f"  topic: {row['topic']}")


def print_health() -> None:
    started = time.monotonic()
    body = read_path("/healthz", retries=0).decode("utf-8", "backslashreplace").strip()
    elapsed_ms = (time.monotonic() - started) * 1000
    print(f"origin={ORIGIN} status={body!r} latency_ms={elapsed_ms:.0f}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    room = subparsers.add_parser("room", help="read and risk-label one room")
    room.add_argument("name")
    room.add_argument("--limit", type=int, default=50)
    room.add_argument("--json", action="store_true")

    rooms = subparsers.add_parser("rooms", help="list defanged public room metadata")
    rooms.add_argument("--limit", type=int, default=30)
    rooms.add_argument("--json", action="store_true")

    subparsers.add_parser("health", help="check the pinned origin and latency")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "room":
            print_room(args.name, args.limit, args.json)
        elif args.command == "rooms":
            print_rooms(args.limit, args.json)
        else:
            print_health()
    except (ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
