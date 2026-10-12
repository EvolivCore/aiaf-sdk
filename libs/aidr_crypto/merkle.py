"""Merkle tree and hash chain for the tamper-evident audit ledger (RFC 6962 construction).

Access controls tell you that a log *should not* have been altered. A Merkle tree lets anyone
prove that it *was not*. That difference is the entire value of this module: it turns "trust our
operational controls" into "check this proof yourself", which is the only version of the claim
that survives an adversarial audit or a disgruntled insider.

Two proofs matter, and they answer different questions:

* **Inclusion** — "is this entry really in the log you published?" Used when showing a customer
  the record of an action taken on their agent.
* **Consistency** — "is the log you publish today a strict append-only extension of the one you
  published last week?" This is the one that catches history being rewritten. Anyone who kept an
  old signed tree head can run it, which is why tree heads are published externally.

Domain separation between leaf hashes (``0x00``) and internal nodes (``0x01``) comes from RFC 6962
and is not decoration: without it, an attacker could present an internal node as if it were a leaf
and forge an inclusion proof for data that was never logged.

This is a reference implementation that recomputes nodes from the full leaf list — O(n) per
operation, correct and easy to audit. Production replaces it with an incremental tree that
persists interior nodes; the test vectors in ``tests/test_merkle.py`` are what will hold that
replacement to the same behaviour.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from aidr_core.errors import LedgerIntegrityError

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def empty_root() -> bytes:
    return hashlib.sha256(b"").digest()


def _largest_power_of_two_below(n: int) -> int:
    """Largest power of two strictly less than n (n > 1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over a sequence of leaf hashes."""
    if not leaves:
        return empty_root()
    if len(leaves) == 1:
        return leaves[0]
    k = _largest_power_of_two_below(len(leaves))
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves: Sequence[bytes], index: int) -> list[bytes]:
    """Audit path for the leaf at ``index`` within ``leaves``."""
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError(f"leaf index {index} out of range for tree of size {n}")
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if index < k:
        return inclusion_proof(leaves[:k], index) + [merkle_root(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, tree_size: int, proof: Sequence[bytes],
                     root: bytes) -> bool:
    """Verify an inclusion proof without access to the tree.

    The RFC 6962 audit path is ordered bottom-up — the sibling nearest the leaf comes first — so
    the walk consumes it in that order, climbing one level per element. ``fn`` tracks the node's
    index within its level and ``sn`` the last index at that level; ``fn == sn`` marks the right
    edge of an unbalanced tree, where the node is a right child even though its index is even.
    """
    if not 0 <= index < tree_size or tree_size <= 0:
        return False
    if tree_size == 1:
        return not proof and leaf == root

    computed = leaf
    fn, sn = index, tree_size - 1

    for sibling in proof:
        if sn == 0:
            return False            # proof is longer than the tree is tall
        if fn % 2 == 1 or fn == sn:
            computed = node_hash(sibling, computed)
            while fn % 2 == 0 and fn != 0:
                fn //= 2
                sn //= 2
        else:
            computed = node_hash(computed, sibling)
        fn //= 2
        sn //= 2

    return sn == 0 and computed == root


def consistency_proof(leaves: Sequence[bytes], old_size: int) -> list[bytes]:
    """Prove that the current tree extends the tree of size ``old_size`` without alteration."""
    n = len(leaves)
    if not 0 < old_size <= n:
        raise ValueError(f"old_size {old_size} out of range for tree of size {n}")
    if old_size == n:
        return []
    return _subproof(leaves, old_size, True)


def _subproof(leaves: Sequence[bytes], m: int, is_complete_subtree: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        # The old tree is exactly this subtree; its root is only needed when the subtree is not
        # already known to the verifier from the old root itself.
        return [] if is_complete_subtree else [merkle_root(leaves)]

    k = _largest_power_of_two_below(n)
    if m <= k:
        return _subproof(leaves[:k], m, is_complete_subtree) + [merkle_root(leaves[k:])]
    return _subproof(leaves[k:], m - k, False) + [merkle_root(leaves[:k])]


def verify_consistency(old_root: bytes, old_size: int, new_root: bytes, new_size: int,
                       proof: Sequence[bytes]) -> bool:
    """Verify that a tree of ``new_size`` really extends the one of ``old_size``.

    A ``False`` here means the log was rewritten, not that it grew. Callers must treat it as an
    integrity incident — see :func:`assert_consistency`.
    """
    if old_size > new_size or old_size < 0:
        return False
    if old_size == new_size:
        return old_root == new_root and not proof
    if old_size == 0:
        return not proof        # every tree extends the empty tree; nothing to prove

    remaining = list(proof)

    # Climb out of the old tree's right spine. When old_size is a power of two the old tree is
    # already a complete subtree of the new one, so its root is NOT carried in the proof and is
    # used directly as the starting hash. Otherwise the first proof element supplies it.
    node, last_node = old_size - 1, new_size - 1
    while node % 2 == 1:
        node //= 2
        last_node //= 2

    if node > 0:
        if not remaining:
            return False
        computed_old = computed_new = remaining.pop(0)
    else:
        computed_old = computed_new = old_root

    while node > 0:
        if node % 2 == 1:
            if not remaining:
                return False
            sibling = remaining.pop(0)
            computed_old = node_hash(sibling, computed_old)
            computed_new = node_hash(sibling, computed_new)
        elif node < last_node:
            if not remaining:
                return False
            computed_new = node_hash(computed_new, remaining.pop(0))
        node //= 2
        last_node //= 2

    # Finish climbing the new tree's right spine; these levels did not exist in the old tree.
    while last_node > 0:
        if not remaining:
            return False
        computed_new = node_hash(computed_new, remaining.pop(0))
        last_node //= 2

    # Leftover proof elements mean the proof does not match the claimed sizes. Accepting a proof
    # with unconsumed material would let an attacker append junk that is never checked.
    return not remaining and computed_old == old_root and computed_new == new_root


def assert_consistency(old_root: bytes, old_size: int, new_root: bytes, new_size: int,
                       proof: Sequence[bytes]) -> None:
    """Raise :class:`LedgerIntegrityError` if consistency does not hold.

    The loudest error in the system. It means either a bug or tampering, and it must page a human
    rather than be retried, swallowed, or degraded past.
    """
    if not verify_consistency(old_root, old_size, new_root, new_size, proof):
        raise LedgerIntegrityError(
            "audit ledger consistency proof failed — the log may have been rewritten",
            old_size=old_size, new_size=new_size,
        )


# ==============================================================================================
# Hash chain (the per-entry link, complementary to the tree)
# ==============================================================================================

def canonical_json(value: Any) -> bytes:
    """Deterministic JSON encoding: sorted keys, no insignificant whitespace.

    Determinism is load-bearing. If two encodings of the same entry can differ by a space, the
    hash chain breaks for reasons that look exactly like tampering.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def compute_entry_hash(entry: dict[str, Any], prev_hash: str) -> str:
    """Hash one ledger entry, chained to its predecessor."""
    material = dict(entry)
    material.pop("entry_hash", None)
    material.pop("tree_head_ref", None)     # assigned after the entry is sealed
    material["prev_hash"] = prev_hash
    return hashlib.sha256(canonical_json(material)).hexdigest()


GENESIS_HASH = "0" * 64


@dataclass
class HashChain:
    """An in-memory append-only hash chain, used to verify a ledger segment."""

    entries: list[dict[str, Any]] = field(default_factory=list)
    head: str = GENESIS_HASH

    def append(self, entry: dict[str, Any]) -> dict[str, Any]:
        sealed = dict(entry)
        sealed["prev_hash"] = self.head
        sealed["entry_hash"] = compute_entry_hash(sealed, self.head)
        self.entries.append(sealed)
        self.head = sealed["entry_hash"]
        return sealed

    def verify(self) -> None:
        """Re-derive every link, raising on the first break."""
        previous = GENESIS_HASH
        for position, entry in enumerate(self.entries):
            if entry.get("prev_hash") != previous:
                raise LedgerIntegrityError(
                    f"hash chain broken at position {position}: prev_hash does not match",
                    position=position, seq=entry.get("seq"),
                )
            expected = compute_entry_hash(entry, previous)
            if entry.get("entry_hash") != expected:
                raise LedgerIntegrityError(
                    f"hash chain broken at position {position}: entry has been modified",
                    position=position, seq=entry.get("seq"),
                )
            previous = entry["entry_hash"]

    def leaves(self) -> list[bytes]:
        return [leaf_hash(bytes.fromhex(e["entry_hash"])) for e in self.entries]

    def root(self) -> bytes:
        return merkle_root(self.leaves())
