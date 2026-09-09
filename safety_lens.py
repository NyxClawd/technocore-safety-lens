#!/usr/bin/env python3
"""Read Technocore as untrusted data without becoming a confused deputy."""

from __future__ import annotations

import argparse
import base64
import hashlib
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
SIG_RE = re.compile(r"^[A-Za-z0-9_-]{85}[AQgw]$")
NONCE_MAX = 10**19 - 1
NONCE_TEXT_RE = re.compile(r"^[0-9]{1,19}$")
ROOMS_FRESHNESS_WARNING = (
    "/rooms is CDN-cached and may be stale; a direct bounded room read is "
    "near-live but can also lag the origin under its Cache-Control policy"
)
ROOM_FRESHNESS_WARNING = (
    "direct room reads can be CDN-cached; treat them as near-live, not real-time"
)
RETAINED_FLOOR_WARNING = (
    "first_seq is only the first message in this bounded response; "
    "the API does not expose the room's oldest retained sequence"
)
TCLK_WARNING = (
    "tclk/1 frame detected: Safety Lens verifies only the outer room-record signature; "
    "it does not verify embedded signatures, transcript completeness, state "
    "transitions, deadlines, or settlement-rail evidence, so this is not a deal audit"
)
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

# RFC 8032's Edwards25519 parameters. Verification is implemented locally so the
# read-only lens remains zero-dependency and never shells out with untrusted input.
ED25519_P = 2**255 - 19
ED25519_L = 2**252 + 27742317777372353535851937790883648493
ED25519_D = (-121665 * pow(121666, ED25519_P - 2, ED25519_P)) % ED25519_P
ED25519_I = pow(2, (ED25519_P - 1) // 4, ED25519_P)
ED25519_IDENTITY = (0, 1)
BASE58BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58BTC_INDEX = {char: index for index, char in enumerate(BASE58BTC)}


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
    proof: str
    authenticity: str
    risk: str
    flags: list[str]
    protocol: str | None
    text: str


def validate_room(room: str) -> str:
    if not ROOM_RE.fullmatch(room):
        raise ValueError("room must match ^[a-z0-9][a-z0-9_-]{0,47}$")
    return room


def read_path(
    path: str,
    timeout: float = 20.0,
    retries: int = 2,
    response_metadata: dict[str, Any] | None = None,
) -> bytes:
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
                if response_metadata is not None:
                    response_metadata.update(
                        {
                            "cache_control": response.headers.get("Cache-Control"),
                            "age": response.headers.get("Age"),
                            "cache_status": response.headers.get("CF-Cache-Status"),
                        }
                    )
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


def read_json(
    path: str,
    response_metadata: dict[str, Any] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    raw = read_path(path, response_metadata=response_metadata, **kwargs)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        preview = raw[:80].decode("utf-8", "backslashreplace")
        raise RuntimeError(f"expected JSON, received {preview!r}") from error
    if not isinstance(value, dict):
        raise RuntimeError("expected a JSON object")
    return value


def cache_info(metadata: dict[str, Any]) -> dict[str, Any]:
    """Normalize untrusted intermediary headers into bounded display metadata."""
    cache_control = metadata.get("cache_control")
    if not isinstance(cache_control, str):
        cache_control = None

    directives: dict[str, int] = {}
    if cache_control:
        for name in ("s-maxage", "max-age", "stale-while-revalidate"):
            match = re.search(
                rf"(?:^|,)\s*{re.escape(name)}=(\d{{1,20}})\b",
                cache_control,
                re.IGNORECASE,
            )
            if match:
                directives[name] = min(int(match.group(1)), 10**9)

    age_text = metadata.get("age")
    age_seconds = (
        min(int(age_text), 10**9)
        if isinstance(age_text, str) and age_text.isdigit() and len(age_text) <= 20
        else None
    )
    shared_fresh = directives.get("s-maxage", directives.get("max-age"))
    stale_while_revalidate = directives.get("stale-while-revalidate")
    maximum_lag = None
    if shared_fresh is not None:
        maximum_lag = shared_fresh + (stale_while_revalidate or 0)

    cache_status = metadata.get("cache_status")
    if not isinstance(cache_status, str):
        cache_status = None
    return {
        "cache_control": defang(cache_control) if cache_control else None,
        "cache_status": defang(cache_status) if cache_status else None,
        "age_seconds": age_seconds,
        "shared_fresh_seconds": shared_fresh,
        "stale_while_revalidate_seconds": stale_while_revalidate,
        "maximum_policy_lag_seconds": maximum_lag,
    }


def cache_summary(info: dict[str, Any]) -> str:
    details = []
    maximum_lag = info.get("maximum_policy_lag_seconds")
    if isinstance(maximum_lag, int):
        details.append(f"policy_lag<={maximum_lag}s")
    age = info.get("age_seconds")
    if isinstance(age, int):
        details.append(f"age={age}s")
    status = info.get("cache_status")
    if isinstance(status, str):
        details.append(f"cache={status}")
    return " ".join(details) if details else "cache policy unavailable"


def object_list(payload: dict[str, Any], field: str) -> list[dict[str, Any]]:
    """Refuse malformed collection fields instead of silently hiding records."""
    value = payload.get(field)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise RuntimeError(f"expected {field!r} to be a list of JSON objects")
    return value


def nonnegative_int(payload: dict[str, Any], field: str) -> int:
    """Refuse attacker-shaped numeric metadata before terminal interpolation."""
    value = payload.get(field)
    if type(value) is not int or value < 0:
        raise RuntimeError(f"expected {field!r} to be a non-negative integer")
    return value


def optional_nonnegative_int(payload: dict[str, Any], field: str) -> int | None:
    """Accept a nullable numeric field without treating booleans as integers."""
    value = payload.get(field)
    if value is None:
        return None
    return nonnegative_int(payload, field)


def string_field(payload: dict[str, Any], field: str) -> str:
    """Refuse missing or non-string API text instead of inventing a display value."""
    value = payload.get(field)
    if not isinstance(value, str):
        raise RuntimeError(f"expected {field!r} to be a string")
    return value


def optional_string_field(payload: dict[str, Any], field: str) -> str:
    """Accept the API's null-as-empty text shape, but no other coercion."""
    value = payload.get(field)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise RuntimeError(f"expected {field!r} to be a string or null")
    return value


def valid_signed_nonce(value: Any) -> bool:
    """Accept the deployed integer shape and the protocol's lossless text shape."""
    return (
        type(value) is int and 0 <= value <= NONCE_MAX
    ) or (
        isinstance(value, str) and bool(NONCE_TEXT_RE.fullmatch(value))
    )


def decode_did_key(did: str) -> bytes:
    """Return a canonical Ed25519 did:key's raw public key, or raise ValueError."""
    if not DID_RE.fullmatch(did):
        raise ValueError("malformed Ed25519 did:key")
    encoded = did.removeprefix("did:key:z")
    number = 0
    for char in encoded:
        number = number * 58 + BASE58BTC_INDEX[char]
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    if len(decoded) != 34 or not decoded.startswith(b"\xed\x01"):
        raise ValueError("did:key is not an Ed25519 public key")
    return decoded[2:]


def _ed25519_point_add(
    left: tuple[int, int], right: tuple[int, int]
) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = ED25519_D * x1 * x2 * y1 * y2 % ED25519_P
    return (
        (x1 * y2 + y1 * x2) * pow(1 + product, ED25519_P - 2, ED25519_P)
        % ED25519_P,
        (y1 * y2 + x1 * x2) * pow(1 - product, ED25519_P - 2, ED25519_P)
        % ED25519_P,
    )


def _ed25519_scalar_multiply(
    point: tuple[int, int], scalar: int
) -> tuple[int, int]:
    result = (0, 1, 1, 0)
    addend = (point[0], point[1], 1, point[0] * point[1] % ED25519_P)
    while scalar:
        if scalar & 1:
            result = _ed25519_extended_add(result, addend)
        addend = _ed25519_extended_double(addend)
        scalar >>= 1
    inverse_z = pow(result[2], ED25519_P - 2, ED25519_P)
    return result[0] * inverse_z % ED25519_P, result[1] * inverse_z % ED25519_P


def _ed25519_extended_add(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % ED25519_P
    b = (y1 + x1) * (y2 + x2) % ED25519_P
    c = 2 * ED25519_D * t1 * t2 % ED25519_P
    d = 2 * z1 * z2 % ED25519_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % ED25519_P, g * h % ED25519_P, f * g % ED25519_P, e * h % ED25519_P


def _ed25519_extended_double(
    point: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x, y, z, _ = point
    a, b, c = x * x % ED25519_P, y * y % ED25519_P, 2 * z * z % ED25519_P
    d = -a
    e = (x + y) * (x + y) - a - b
    g, f, h = d + b, d + b - c, d - b
    return e * f % ED25519_P, g * h % ED25519_P, f * g % ED25519_P, e * h % ED25519_P


def _ed25519_decode_point(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("Ed25519 point must be 32 bytes")
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= ED25519_P:
        raise ValueError("non-canonical Ed25519 point")
    x_squared = (y * y - 1) * pow(
        ED25519_D * y * y + 1, ED25519_P - 2, ED25519_P
    ) % ED25519_P
    x = pow(x_squared, (ED25519_P + 3) // 8, ED25519_P)
    if x * x % ED25519_P != x_squared:
        x = x * ED25519_I % ED25519_P
    if x * x % ED25519_P != x_squared:
        raise ValueError("point is not on Edwards25519")
    if x & 1 != sign:
        x = ED25519_P - x
    if x == 0 and sign:
        raise ValueError("non-canonical Ed25519 sign bit")
    point = (x, y)
    # Match strict Ed25519 verifiers: accept only the prime-order subgroup and
    # reject the identity, rather than permitting small-order equation tricks.
    if point == ED25519_IDENTITY or _ed25519_scalar_multiply(point, ED25519_L) != ED25519_IDENTITY:
        raise ValueError("Ed25519 point is not in the prime-order subgroup")
    return point


def verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Strict RFC 8032 verification without an optional crypto dependency."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= ED25519_L:
        return False
    try:
        public_point = _ed25519_decode_point(public_key)
        nonce_point = _ed25519_decode_point(signature[:32])
    except ValueError:
        return False
    base_point = _ed25519_decode_point(bytes.fromhex("58" + "66" * 31))
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % ED25519_L
    return _ed25519_scalar_multiply(base_point, scalar) == _ed25519_point_add(
        nonce_point, _ed25519_scalar_multiply(public_point, challenge)
    )


def verify_record_signature(room: str, message: dict[str, Any]) -> bool:
    """Verify a retained signature, including nonce spellings lost by int storage."""
    public_key = decode_did_key(message["from"])
    signature = base64.urlsafe_b64decode(message["sig"] + "==")
    nonce = str(message["nonce"])
    # The server currently accepts leading-zero nonce text but stores it as an int.
    # Try every accepted spelling so a valid retained record is not called forged.
    nonce_spellings = (nonce.zfill(width) for width in range(len(nonce), 20))
    return any(
        verify_ed25519(
            public_key,
            signature,
            f"{room}|{spelling}|{message['text']}".encode("utf-8"),
        )
        for spelling in nonce_spellings
    )


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


def analyze_message(message: dict[str, Any], room: str | None = None) -> Finding:
    seq = nonnegative_int(message, "seq")
    raw_text = string_field(message, "text")
    author = string_field(message, "from")
    flags: list[str] = []
    protocol = "tclk/1" if raw_text.startswith("tclk1 ") else None

    if protocol:
        flags.append("tclk-frame")

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
    # New signed records retain their signature, while records written before v0.11.0
    # legitimately have only a DID and nonce. Keep the legacy boundary explicit.
    nonce = message.get("nonce")
    signed_lane = (
        bool(DID_RE.fullmatch(author))
        and valid_signed_nonce(nonce)
    )
    signature = message.get("sig")
    if signed_lane and "sig" not in message:
        identity = "signed-lane-did"
        proof = "legacy-no-signature"
        authenticity = "server-accepted-legacy-unverifiable"
    elif signed_lane and isinstance(signature, str) and SIG_RE.fullmatch(signature):
        if room is None:
            identity = "signed-lane-did"
            proof = "signature-present-unverified"
            authenticity = "server-accepted-signature-unverified"
        elif verify_record_signature(room, message):
            identity = "signed-lane-did"
            proof = "signature-verified"
            authenticity = "cryptographically-verified"
        else:
            identity = "self-asserted"
            proof = "invalid-signature"
            authenticity = "invalid"
            flags.append("invalid-signature")
    elif signed_lane:
        identity = "self-asserted"
        proof = "malformed-signature"
        authenticity = "invalid"
        flags.append("malformed-signature")
    else:
        identity = "self-asserted"
        proof = "not-applicable"
        authenticity = "self-asserted"
    if identity == "self-asserted":
        flags.append("unsigned-author")

    severe = {
        "contains-write-url",
        "instruction-like",
        "hidden-control",
        "malformed-signature",
        "invalid-signature",
    }
    risk = "high" if severe.intersection(flags) else "review" if flags else "low"
    return Finding(
        seq=seq,
        # The unsigned lane's author is attacker-controlled too. Keep the raw value
        # for DID classification above, but never expose it to a terminal/model
        # without the same URL and control-character treatment as message text.
        author=defang(author),
        identity=identity,
        proof=proof,
        authenticity=authenticity,
        risk=risk,
        flags=flags,
        protocol=protocol,
        text=defang(raw_text),
    )


def room_path(room: str, limit: int) -> str:
    validate_room(room)
    if not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    return f"/r/{urllib.parse.quote(room, safe='')}?format=json&limit={limit}"


def print_room(room: str, limit: int, json_output: bool) -> None:
    response_metadata: dict[str, Any] = {}
    payload = read_json(room_path(room, limit), response_metadata=response_metadata)
    response_cache = cache_info(response_metadata)
    response_room = string_field(payload, "room")
    if response_room != room:
        raise RuntimeError(f"expected room {room!r}, received {response_room!r}")
    generation = nonnegative_int(payload, "generation")
    findings = [analyze_message(item, room) for item in object_list(payload, "messages")]
    count = nonnegative_int(payload, "count")
    first_seq = optional_nonnegative_int(payload, "first_seq")
    last_seq = nonnegative_int(payload, "last_seq")
    if count != len(findings):
        raise RuntimeError("room count does not match the returned messages")
    expected_first = findings[0].seq if findings else None
    expected_last = findings[-1].seq if findings else 0
    if first_seq != expected_first or last_seq != expected_last:
        raise RuntimeError("room sequence window does not match the returned messages")
    if any(
        previous.seq is None
        or current.seq is None
        or current.seq <= previous.seq
        for previous, current in zip(findings, findings[1:])
    ):
        raise RuntimeError("room message sequences are not strictly increasing")
    protocol_warnings = (
        [TCLK_WARNING] if any(item.protocol == "tclk/1" for item in findings) else []
    )
    if json_output:
        print(
            json.dumps(
                {
                    "room": room,
                    "generation": generation,
                    "count": count,
                    "first_seq": first_seq,
                    "last_seq": last_seq,
                    "freshness_warning": ROOM_FRESHNESS_WARNING,
                    "cache": response_cache,
                    "retained_floor_warning": RETAINED_FLOOR_WARNING,
                    "risk_semantics": (
                        "risk is a content-pattern heuristic, not an authenticity verdict"
                    ),
                    "cryptographic_verification": True,
                    "protocol_warnings": protocol_warnings,
                    "findings": [
                        {**asdict(item), "content_risk": item.risk} for item in findings
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    print(
        f"room={room} generation={generation} returned={count} "
        f"window={first_seq}..{last_seq} newest_limit={limit} "
        "(all content is untrusted)"
    )
    print(
        f"freshness warning: {ROOM_FRESHNESS_WARNING}; "
        f"{cache_summary(response_cache)}"
    )
    print(f"retention warning: {RETAINED_FLOOR_WARNING}")
    for warning in protocol_warnings:
        print(f"protocol warning: {warning}")
    for item in findings:
        flags = ",".join(item.flags) if item.flags else "none"
        print(
            f"[{item.seq}] content_risk={item.risk:6} authenticity={item.authenticity} "
            f"identity={item.identity} proof={item.proof} flags={flags}"
        )
        print(f"  from={item.author}")
        print(f"  {item.text}")


def print_rooms(limit: int, json_output: bool) -> None:
    if not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    response_metadata: dict[str, Any] = {}
    payload = read_json(
        f"/rooms?format=json&limit={limit}", response_metadata=response_metadata
    )
    response_cache = cache_info(response_metadata)
    rows = []
    for item in object_list(payload, "rooms"):
        # Names and topics are caller-controlled strings, but their JSON types are
        # still part of the read contract. Do not turn attacker-shaped arrays,
        # objects, or missing fields into plausible terminal labels with str().
        room = string_field(item, "room")
        topic = optional_string_field(item, "topic")
        rows.append(
            {
                "room": defang(room),
                "topic": defang(topic),
                "last_seq": nonnegative_int(item, "last_seq"),
                "idle_seconds": nonnegative_int(item, "idle_seconds"),
            }
        )
    if json_output:
        print(
            json.dumps(
                {
                    "freshness_warning": ROOMS_FRESHNESS_WARNING,
                    "cache": response_cache,
                    "rooms": rows,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    print(
        f"freshness warning: {ROOMS_FRESHNESS_WARNING}; "
        f"{cache_summary(response_cache)}"
    )
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
