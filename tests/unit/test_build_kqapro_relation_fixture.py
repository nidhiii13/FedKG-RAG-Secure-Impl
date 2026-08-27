from scripts.build_kqapro_relation_fixture import (
    closure_for_queries,
    contiguous_entity_ids,
    owner_for,
    public_primary_types,
    relation_domains,
    make_queries,
)


def tiny_kb():
    return {
        "concepts": {
            "Cperson": {"name": "person", "instanceOf": []},
            "Cplace": {"name": "place", "instanceOf": []},
        },
        "entities": {
            "Qalice": {"name": "Alice", "instanceOf": ["Cperson"], "relations": []},
            "Qbob": {"name": "Bob", "instanceOf": ["Cperson"], "relations": []},
            "Qcity": {"name": "City", "instanceOf": ["Cplace"], "relations": []},
        },
    }


def test_public_types_produce_contiguous_deterministic_ids():
    primary = public_primary_types(tiny_kb())
    ids = contiguous_entity_ids(primary)
    assert sorted(ids.values()) == list(range(1, len(ids) + 1))
    for node_a, slot_a in ids.items():
        for node_b, slot_b in ids.items():
            if primary[node_a] == primary[node_b]:
                members = sorted(ids[node] for node in ids if primary[node] == primary[node_a])
                assert members == list(range(members[0], members[-1] + 1))


def test_relation_domain_and_closure_use_paths_not_answers():
    triples = [
        ("Qalice", "lives", "Qcity"),
        ("Qcity", "resident_inverse", "Qalice"),
        ("Qcity", "resident_inverse", "Qbob"),
        ("Qbob", "unrelated", "Qalice"),
    ]
    primary = public_primary_types(tiny_kb())
    domains = relation_domains(triples, primary)
    assert domains["lives"] == "Cperson"
    closure = closure_for_queries(
        triples,
        [{"source": "Qalice", "relation_1": "lives", "relation_2": "resident_inverse"}],
    )
    assert closure == set(triples[:3])


def test_synthetic_owner_split_is_stable():
    triple = ("Qalice", "lives", "Qcity")
    assert owner_for(triple) == owner_for(triple)


def test_make_queries_can_select_validation_or_all_compatible_splits():
    rows = [
        {"split": "train", "path_equivalent": True, "source_id": "Q1",
         "relation_1": "r1", "relation_2": "r2", "uid": "train:1",
         "question": "train?", "answer": "a", "endpoint_ids": ["Q3"]},
        {"split": "val", "path_equivalent": True, "source_id": "Q4",
         "relation_1": "r1", "relation_2": "r2", "uid": "val:1",
         "question": "val?", "answer": "b", "endpoint_ids": ["Q6"]},
    ]
    validation, _ = make_queries(rows)
    all_queries, _ = make_queries(rows, ("train", "val"))
    assert len(validation) == 1
    assert len(all_queries) == 2
