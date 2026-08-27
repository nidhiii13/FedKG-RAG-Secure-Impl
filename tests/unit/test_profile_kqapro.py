from scripts.profile_kqapro import CHAIN_FUNCTIONS, KQAIndex, chain_rejection, profile


def tiny_kb(extra_untyped_answer: bool = False):
    relations = [
        {
            "predicate": "r1",
            "object": "Qmid",
            "direction": "forward",
            "qualifiers": {},
        }
    ]
    middle_relations = [
        {
            "predicate": "r2",
            "object": "Qanswer",
            "direction": "forward",
            "qualifiers": {},
        }
    ]
    entities = {
        "Qsource": {"name": "Source", "instanceOf": [], "attributes": [], "relations": relations},
        "Qmid": {
            "name": "Middle",
            "instanceOf": ["Cmid"],
            "attributes": [],
            "relations": middle_relations,
        },
        "Qanswer": {
            "name": "Answer",
            "instanceOf": ["Canswer"],
            "attributes": [],
            "relations": [],
        },
    }
    if extra_untyped_answer:
        entities["Qother"] = {
            "name": "Other",
            "instanceOf": ["Cother"],
            "attributes": [],
            "relations": [],
        }
        middle_relations.append(
            {
                "predicate": "r2",
                "object": "Qother",
                "direction": "forward",
                "qualifiers": {},
            }
        )
    return {
        "concepts": {
            "Croot": {"name": "root", "instanceOf": []},
            "Cmid": {"name": "middle type", "instanceOf": ["Croot"]},
            "Canswer": {"name": "answer type", "instanceOf": ["Croot"]},
            "Cother": {"name": "other type", "instanceOf": ["Croot"]},
        },
        "entities": entities,
    }


def chain_program():
    functions = CHAIN_FUNCTIONS
    inputs = [
        ["Source"],
        ["r1", "forward"],
        ["middle type"],
        ["r2", "forward"],
        ["answer type"],
        [],
    ]
    return [
        {
            "function": function,
            "dependencies": [] if index == 0 else [index - 1],
            "inputs": inputs[index],
        }
        for index, function in enumerate(functions)
    ]


def test_chain_rejection_is_conservative():
    assert chain_rejection(chain_program()) is None
    program = chain_program()
    program.insert(3, {"function": "Count", "dependencies": [2], "inputs": []})
    assert chain_rejection(program) == "unsupported_operator_or_shape"


def test_concept_ancestry_and_directional_relate():
    index = KQAIndex(tiny_kb())
    assert index.matches_concept("Qmid", "middle type")
    assert index.matches_concept("Qmid", "root")
    assert index.relate({"Qsource"}, "r1", "forward") == {"Qmid"}
    assert index.relate({"Qsource"}, "r1", "backward") == set()


def test_profile_accepts_only_snapshot_equivalent_paths(tmp_path):
    row = {
        "question": "Who is reached?",
        "answer": "Answer",
        "choices": ["Answer"],
        "program": chain_program(),
        "sparql": "SELECT ...",
    }
    accepted = profile(tiny_kb(), {"val": [row]}, tmp_path / "accepted")
    rejected = profile(tiny_kb(extra_untyped_answer=True), {"val": [row]}, tmp_path / "rejected")
    assert accepted["syntactic_candidates"] == 1
    assert accepted["snapshot_path_equivalent"] == 1
    assert rejected["syntactic_candidates"] == 1
    assert rejected["snapshot_path_equivalent"] == 0
    assert rejected["candidate_outcomes"] == {"answer_concept_filter_changes_result": 1}
