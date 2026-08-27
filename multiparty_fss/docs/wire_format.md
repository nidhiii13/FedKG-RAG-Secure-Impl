# Wire Formats — `multiparty_fss/` (all versioned, all fail-closed)

Encoding: JSON objects parsed with the standard `json` module followed by an
explicit schema walk (exact field set, exact types, exact lengths). **No
regular expressions touch security-relevant input.** Unknown fields are
rejected, not ignored. Binary payloads are base64 (`validate=True`) of
fixed-length little-endian encodings whose lengths are recomputed from the
declared parameters and must match exactly. All version strings are disjoint
from the legacy two-party path's (`fedkg-mpfss-*` vs `fedkg-fss-*` /
untagged CLI payloads), so cross-path material is structurally rejected.

Identifiers:

| Constant | Value |
|---|---|
| Construction | `bgi15-mpdpf-p0` |
| Output group | `xor64` (GF(2)^64; combine = XOR) — the legacy path's `uint64` (Z/2^64) is rejected |
| PRG | `shake256-v1` |
| Key wire version | `fedkg-mpfss-key-v1` |
| Request version | `fedkg-mpfss-request-v1` |
| Response version | `fedkg-mpfss-response-v1` |
| Store manifest version | `fedkg-mpfss-replica-manifest-v1` |
| Projection version | `fedkg-mpfss-xor-projection-v1` |
| Universe digest | same algorithm/label as the legacy path (`fedkg-fss-universe-v1` — a hash of public data, deliberately comparable across paths) |

## Key share (`keyshare.MpDpfKeyShare`)

| Field | Type | Meaning / validation |
|---|---|---|
| `version` | str | must equal `fedkg-mpfss-key-v1` |
| `construction` | str | must equal `bgi15-mpdpf-p0` |
| `params_id` | hex64 | SHA-256 of the canonical parameter set; recomputed and compared — a tampered N/t/n cannot slip through |
| `party_count` | int | N ∈ [3, 10] |
| `threshold` | int | claimed t, 1 ≤ t ≤ N−1 (default ⌊(N−1)/2⌋) |
| `party_index` | int | this evaluator's index ∈ [0, N) |
| `domain_bits` | int | n ∈ [1, 30] |
| `output_group` | str | must equal `xor64` |
| `prg` | str | must equal `shake256-v1` |
| `keygen_id` | hex32 | fresh per `Gen` invocation; mixing generations is rejected |
| `domain_binding` | `"raw"` or hex64 | universe digest the key is bound to; the evaluator service refuses `"raw"` and requires equality with its own digest |
| `sigma` | base64 | exactly ν·2^{p−1}·16 bytes; the party's seed blocks (all-zero block = seed not held) |
| `correction_words` | base64 | exactly 2^{p−1}·μ·8 bytes; little-endian uint64 words |

## Evaluator request (`requests.MpFssEvaluatorRequest`)

`version`, `construction`, `request_id` (non-empty), `domain` (one of
`entity`, `relation`, `type`, `frontier`, `relation_bucket`,
`entity_bucket`), `evaluator_id`, `party_index`, `party_count`, `threshold`,
`key_share` (embedded key-share object), `projection` (object or null).
Parse-time cross-checks: request N/t/party_index must equal the embedded key
share's. Service-time cross-checks: evaluator identity, party index, N, t
against the store manifest; key `domain_binding` and `domain_bits` against
the store's universe.

## Evaluator response (`requests.MpFssEvaluatorResponse`)

`version`, `construction`, `request_id`, `evaluator_id`, `party_index`,
`party_count`, `threshold`, `params_id`, `keygen_id`, `domain`,
`output_group`, `universe_digest` (hex64), `payload_kind`
(`dense` | `projected`), and exactly one payload:

- dense: `point_count` + `value_shares` (length == point_count), other
  fields null;
- projected: `projection_digest` (hex64) + `slot_handles` (unique) +
  `candidate_slot_shares` (length == slots), other fields null.

Every share value must be an int in [0, 2^64). Booleans are rejected
everywhere an int is required.

## Coordinator validation matrix (`requests.MpFssCoordinator.combine`)

N and t are constructor arguments (explicit configuration — never inferred
from the input). Rejected, in order: response count ≠ N; party indices ≠
{0..N−1} exactly (missing / duplicate / out-of-range); non-distinct
evaluator IDs; any response whose `party_count`/`threshold` differs from
configuration; mismatch across responses of any of `request_id`,
`params_id`, `keygen_id`, `domain`, `universe_digest`, `payload_kind`,
`projection_digest`, `slot_handles`, `point_count`; mismatch with the
caller's `expected_request_id`; share-vector length mismatch. Combination is
element-wise XOR over all N vectors.

## Store manifest (`replication.MpEvaluatorManifest`)

`version`, `construction`, `evaluator_id`, `party_index`, `party_count`,
`threshold`, `evaluator_ids` (ordered list, length N, unique; position =
party index; `evaluator_ids[party_index]` must equal `evaluator_id`),
`snapshots` (list of `{partition_id, digest, relative_path}`; each snapshot
re-hashed at load and compared; paths must stay inside the store root).
Legacy `fedkg-fss-replica-manifest-v1` stores are rejected with an explicit
message.

## XOR projection (`projection.XorCandidateProjection`)

`version`, `slot_handles` (unique), `point_slots` (point → list of target
slots, no duplicate targets, all targets known). Applied by XORing each
point's output share into each routed slot; weights are implicitly 1 (the
conversion from the legacy layout builder refuses any other weight).
`digest()` = SHA-256 of the canonical JSON. The legacy additive projection
(`point_weights`, no `version`) is structurally rejected.

## What the bindings do and do not provide

They make misrouting, replay-across-context, cross-generation mixing,
cross-construction confusion, truncation, and topology drift **detectable
and rejected**. They do not authenticate anyone: transport confidentiality
and authenticity are deployment assumptions (SECURITY.md), and a semi-honest
model provides no defense against a party that lies inside a well-formed
envelope.
