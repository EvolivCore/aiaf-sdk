"""Recursive conversion between dataclasses and JSON/BSON-compatible structures.

The registry's domain models are plain dataclasses rather than Pydantic models, so that
``aidr_core`` carries no third-party dependency and can be imported by anything — a Lambda-sized
verifier, a migration script, a test harness. The HTTP layer converts to Pydantic at the edge,
where request validation actually belongs.

Datetimes round-trip as RFC 3339 strings with an explicit offset. Naive datetimes are rejected
rather than assumed to be UTC: a timestamp whose timezone was guessed is a timestamp that will be
wrong by hours exactly once, in production, during an incident.
"""

from __future__ import annotations

import dataclasses
import types
import typing
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TypeVar, Union, get_args, get_origin

T = TypeVar("T")

_HINT_CACHE: dict[type, dict[str, Any]] = {}


def _hints(cls: type) -> dict[str, Any]:
    """Resolve and cache a dataclass's type hints.

    Cached because ``get_type_hints`` re-evaluates every annotation string on each call, which is
    measurable when deserialising thousands of records in a migration.
    """
    if cls not in _HINT_CACHE:
        _HINT_CACHE[cls] = typing.get_type_hints(cls)
    return _HINT_CACHE[cls]


def to_jsonable(value: Any) -> Any:
    """Convert dataclasses, enums, datetimes and containers into JSON-compatible values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("naive datetime rejected — attach an explicit timezone")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, bytes):
        import base64

        return base64.b64encode(value).decode("ascii")
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_jsonable(v) for v in value]
    # Anything reaching here (an ObjectId, a custom type) must be handled explicitly rather than
    # stringified by accident — silent coercion is how a field's type quietly changes in prod.
    raise TypeError(f"cannot serialise value of type {type(value).__name__}")


def parse_datetime(value: Any) -> datetime:
    """Parse an RFC 3339 string or pass through an aware datetime."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("naive datetime rejected — attach an explicit timezone")
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            raise ValueError(f"datetime {value!r} has no timezone offset")
        return parsed.astimezone(timezone.utc)
    raise TypeError(f"cannot parse datetime from {type(value).__name__}")


def _from_jsonable(annotation: Any, value: Any) -> Any:
    origin = get_origin(annotation)

    # Optional[X] / X | None / unions
    if origin is Union or origin is types.UnionType:
        args = [a for a in get_args(annotation) if a is not type(None)]
        if value is None:
            return None
        if len(args) == 1:
            return _from_jsonable(args[0], value)
        # Ambiguous unions are a modelling smell; pass through rather than guess a branch.
        return value

    if origin in (list, set, frozenset, tuple):
        args = get_args(annotation)
        item_type = args[0] if args else Any
        items = [_from_jsonable(item_type, v) for v in (value or [])]
        return origin(items) if origin is not tuple else tuple(items)

    if origin is dict:
        args = get_args(annotation)
        value_type = args[1] if len(args) == 2 else Any
        return {k: _from_jsonable(value_type, v) for k, v in (value or {}).items()}

    if annotation is datetime:
        return parse_datetime(value) if value is not None else None

    if isinstance(annotation, type):
        if issubclass(annotation, Enum):
            return annotation(value)
        if dataclasses.is_dataclass(annotation):
            return from_jsonable(annotation, value) if value is not None else None
        if annotation is bytes and isinstance(value, str):
            import base64

            return base64.b64decode(value)

    return value


def from_jsonable(cls: type[T], data: dict | None) -> T:
    """Reconstruct a dataclass instance from a plain dict.

    Unknown keys are ignored rather than rejected. That is deliberate: during a rolling deploy,
    an older service will read documents written by a newer one, and it must not crash on a field
    it has not learned about yet. Forward compatibility beats strictness for stored data — the
    opposite of the rule we apply to inbound HTTP requests, which are validated strictly at the
    edge.
    """
    if data is None:
        raise ValueError(f"cannot build {cls.__name__} from None")
    hints = _hints(cls)
    kwargs: dict[str, Any] = {}
    for field in dataclasses.fields(cls):
        if field.name not in data:
            continue
        kwargs[field.name] = _from_jsonable(hints.get(field.name, Any), data[field.name])
    return cls(**kwargs)  # type: ignore[arg-type]


def utcnow() -> datetime:
    """Timezone-aware current time. The only source of 'now' in the codebase.

    Centralised so tests can monkeypatch one symbol, and so no call site can accidentally
    introduce a naive datetime.
    """
    return datetime.now(timezone.utc)
