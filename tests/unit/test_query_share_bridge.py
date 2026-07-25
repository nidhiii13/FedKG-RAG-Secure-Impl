from src.crypto.hmac_ids import HmacIdProvider
from src.gateway.query_share_bridge import MpcQueryShareBridge


def test_query_share_bridge_splits_hmac_tokens_and_preserves_unknowns() -> None:
    bridge = MpcQueryShareBridge(
        HmacIdProvider(b"unit-test-setup-key"),
        share_count=3,
    )

    result = bridge.share_edges([("Kismet", "acted in", "UNKNOWN")])

    assert result.share_count == 3
    assert result.token_count == 3
    assert result.non_unknown_token_count == 2
    assert result.tokens[0].encoded_id is not None
    assert result.tokens[1].encoded_id is not None
    assert result.tokens[2].encoded_id is None
    assert result.tokens[2].shares == (0, 0, 0)


def test_query_share_bridge_metadata_does_not_emit_raw_shares_or_labels() -> None:
    bridge = MpcQueryShareBridge(
        HmacIdProvider(b"unit-test-setup-key"),
        share_count=3,
    )

    metadata = bridge.share_edges([("Kismet", "acted in", "UNKNOWN")]).public_metadata()

    assert metadata["mode"] == "local-mpc-query-share-validation"
    assert "Kismet" not in str(metadata)
    assert "acted in" not in str(metadata)
    assert "shares" not in metadata["token_commitments"][0]
    assert "share_commitments" in metadata["token_commitments"][0]
