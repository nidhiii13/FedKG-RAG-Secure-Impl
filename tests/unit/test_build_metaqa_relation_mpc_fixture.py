from collections import defaultdict

import pytest

from scripts.build_metaqa_relation_mpc_fixture import parse_question
from scripts.run_cwq_mpc_domain_worker import acquire_worker_lock


def adjacency(*triples):
    result = defaultdict(list)
    for source, relation, target in triples:
        result[(source, relation)].append(target)
    return result


def test_template_parser_orients_actor_to_movie_without_gold_answers():
    graph = adjacency(
        ("Actor", "starred_actors_inverse", "Film"),
        ("Film", "directed_by", "Director"),
    )
    query, status = parse_question(
        "who is listed as director of [Actor] starred movies", graph
    )
    assert status == "parsed"
    assert query == {
        "source": "Actor",
        "relation_1": "starred_actors_inverse",
        "relation_2": "directed_by",
    }


def test_template_parser_handles_same_director_from_movie_anchor():
    graph = adjacency(
        ("Film A", "directed_by", "Director"),
        ("Director", "directed_by_inverse", "Film B"),
    )
    query, status = parse_question(
        "the director of [Film A] is also the director of which movies", graph
    )
    assert status == "parsed"
    assert query == {
        "source": "Film A",
        "relation_1": "directed_by",
        "relation_2": "directed_by_inverse",
    }


def test_worker_lock_rejects_duplicate_home(tmp_path):
    first = acquire_worker_lock(tmp_path)
    with pytest.raises(RuntimeError, match="another domain worker"):
        acquire_worker_lock(tmp_path)
    first.close()
    second = acquire_worker_lock(tmp_path)
    second.close()
