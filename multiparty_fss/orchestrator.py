"""Client-side orchestrator for one N-party private lookup.

Role: the query CLIENT. It (a) derives the shared universe and verifies that
every evaluator store serves the identical universe (all-N digest equality —
strictly stronger than the legacy path, which trusted store 0's index for
projection building), (b) generates the N key shares locally, (c) dispatches
exactly one share to each evaluator, and (d) combines the N responses through
the fail-closed coordinator. The reconstructed slot values exist only in this
component — evaluators never see each other's outputs.

If the queried opaque ID is not in the shared universe, keys are generated
for the zero function (alpha=0, beta=0) instead of failing: the evaluators'
view is identically distributed either way (BGI15 Definition 2 hides (alpha,
beta), and the zero point function is in the shared family), and the combined
result is correctly all-zero. Failing instead would leak universe membership
of the queried ID through observable behavior.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Sequence

from src.aggregation.prio3_candidates import SessionCandidateHandleProvider

from multiparty_fss.domain import UniverseDomain
from multiparty_fss.errors import RequestValidationError, StoreError
from multiparty_fss.keygen import generate
from multiparty_fss.projection import BuiltXorProjection, build_xor_projection
from multiparty_fss.requests import CombinedXorSlots, MpFssCoordinator, MpFssEvaluatorRequest
from multiparty_fss.service import MultipartyFssEvaluatorService


@dataclass(frozen=True)
class MultipartyFssQueryResult:
    request_id: str
    domain: str
    party_count: int
    threshold: int
    alpha_in_universe: bool
    candidate_values: dict[str, int]
    combined: CombinedXorSlots
    built_projection: BuiltXorProjection


@dataclass(frozen=True)
class MultipartyFssQueryOrchestrator:
    services: Sequence[MultipartyFssEvaluatorService]
    handles: SessionCandidateHandleProvider

    def _validated_topology(self) -> tuple[int, int]:
        if not self.services:
            raise StoreError("no evaluator services configured")
        stores = [service.store for service in self.services]
        party_count = stores[0].party_count
        threshold = stores[0].threshold
        evaluator_ids = stores[0].evaluator_ids
        if len(stores) != party_count:
            raise StoreError(
                f"exactly {party_count} evaluator services are required; "
                f"got {len(stores)}"
            )
        indices = sorted(store.party_index for store in stores)
        if indices != list(range(party_count)):
            raise StoreError(
                "evaluator services must cover party indices "
                f"0..{party_count - 1} exactly once"
            )
        for store in stores:
            if (
                store.party_count != party_count
                or store.threshold != threshold
                or store.evaluator_ids != evaluator_ids
            ):
                raise StoreError("evaluator stores disagree on the topology manifest")
        return party_count, threshold

    def query(
        self,
        request_id: str,
        domain: str,
        alpha_point: str,
        capacity: int,
        beta: int = 1,
    ) -> MultipartyFssQueryResult:
        if not request_id:
            request_id = secrets.token_hex(16)
        party_count, threshold = self._validated_topology()
        by_index = {service.store.party_index: service for service in self.services}

        universes = {
            service.store.party_index: service.store.universe(domain)
            for service in self.services
        }
        digests = {universe.digest() for universe in universes.values()}
        if len(digests) != 1:
            raise StoreError(
                "evaluator stores serve different universes for this domain; "
                "refusing to query"
            )
        universe: UniverseDomain = universes[0]
        digest = universe.digest()

        rank = universe.rank_of(alpha_point.lower())
        alpha_in_universe = rank is not None
        effective_alpha = rank if rank is not None else 0
        effective_beta = beta if rank is not None else 0

        params = universe.params(party_count, threshold)
        key_shares = generate(
            effective_alpha,
            effective_beta,
            party_count,
            threshold,
            params=params,
            domain_binding=digest,
        )

        built = build_xor_projection(
            by_index[0].store.index, self.handles, domain, capacity
        )
        projection_payload = built.projection.as_dict()

        responses = []
        for index in range(party_count):
            service = by_index[index]
            request = MpFssEvaluatorRequest(
                request_id=request_id,
                domain=domain,
                evaluator_id=service.store.evaluator_id,
                party_index=index,
                party_count=party_count,
                threshold=threshold,
                key_share=key_shares[index],
                projection=projection_payload,
            )
            responses.append(service.evaluate(request))

        combined = MpFssCoordinator(party_count, threshold).combine(
            responses, expected_request_id=request_id
        )
        if combined.universe_digest != digest:
            raise RequestValidationError(
                "combined response universe digest does not match the client view"
            )
        return MultipartyFssQueryResult(
            request_id=request_id,
            domain=domain,
            party_count=party_count,
            threshold=threshold,
            alpha_in_universe=alpha_in_universe,
            candidate_values=built.candidate_values(combined.nonzero_slots),
            combined=combined,
            built_projection=built,
        )
