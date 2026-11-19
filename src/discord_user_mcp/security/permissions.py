"""Risk classification for every operation.

The classification is fixed in code, not chosen by the model. Anything the
server cannot classify is treated as ``SENSITIVE`` - the safest assumption.
"""

from __future__ import annotations

from enum import Enum


class Risk(str, Enum):
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"
    SENSITIVE = "sensitive"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return {
            Risk.READ: 0,
            Risk.WRITE: 1,
            Risk.ADMIN: 2,
            Risk.DESTRUCTIVE: 3,
            Risk.SENSITIVE: 4,
        }[self]

    @property
    def requires_approval(self) -> bool:
        return self is not Risk.READ

    @property
    def requires_typed_confirmation(self) -> bool:
        """High impact actions need the operator to type APPROVE, not just click."""
        return self in {Risk.DESTRUCTIVE, Risk.SENSITIVE, Risk.ADMIN}

    @property
    def label(self) -> str:
        return {
            Risk.READ: "read-only",
            Risk.WRITE: "writes to Discord",
            Risk.ADMIN: "guild administration",
            Risk.DESTRUCTIVE: "destructive",
            Risk.SENSITIVE: "account / relationship change",
        }[self]

    @classmethod
    def coerce(cls, value: object) -> "Risk":
        """Never guess: unknown values become SENSITIVE."""
        if isinstance(value, Risk):
            return value
        if isinstance(value, str):
            try:
                return cls(value.strip().lower())
            except ValueError:
                return cls.SENSITIVE
        return cls.SENSITIVE


APPROVAL_PHRASE = "APPROVE"


def describe_policy() -> dict[str, object]:
    return {
        "read": "executed immediately, no approval",
        "write": "requires approval in the local console",
        "admin": "requires approval plus typing APPROVE (guild administration)",
        "destructive": "requires approval plus typing APPROVE (deletes / kicks / bans)",
        "sensitive": "requires approval plus typing APPROVE (account, profile, relationships)",
        "default": "unclassified operations are treated as sensitive",
    }
