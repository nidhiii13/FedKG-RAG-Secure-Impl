from scripts.profile_cwq import extract_chain, map_anchor, parse_sparql

PREFIX = "PREFIX ns: <http://rdf.freebase.com/ns/>\nSELECT DISTINCT ?x\nWHERE {\n"
BOILER = ("FILTER (?x != ?c)\n"
          "FILTER (!isLiteral(?x) OR lang(?x) = '' OR langMatches(lang(?x), 'en'))\n")


def classify(body: str, boiler: bool = True):
    return extract_chain(parse_sparql(PREFIX + (BOILER if boiler else "") + body + "}\n"))


def test_forward_forward_chain():
    category, chain = classify(
        "ns:m.0abc ns:music.artist.origin ?y .\n"
        "?y ns:location.location.time_zones ?x .\n"
    )
    assert category == "strict_two_hop"
    assert chain == {
        "anchor_mid": "m.0abc",
        "relation_1": "music.artist.origin",
        "relation_2": "location.location.time_zones",
    }


def test_inverse_first_hop():
    category, chain = classify(
        "?c ns:sports.sports_team.team_mascot ns:m.03_dwn .\n"
        "?c ns:sports.sports_team.championships ?x .\n"
    )
    assert category == "strict_two_hop"
    assert chain["relation_1"] == "sports.sports_team.team_mascot_inverse"
    assert chain["relation_2"] == "sports.sports_team.championships"


def test_inverse_second_hop():
    category, chain = classify(
        "ns:m.0abc ns:r.one ?y .\n"
        "?x ns:r.two ?y .\n"
    )
    assert category == "strict_two_hop"
    assert chain["relation_2"] == "r.two_inverse"


def test_triple_order_does_not_matter():
    category, chain = classify(
        "?y ns:r.two ?x .\n"
        "ns:m.0abc ns:r.one ?y .\n"
    )
    assert category == "strict_two_hop"
    assert chain["relation_1"] == "r.one"


def test_rejects_conjunction_join():
    category, _ = classify(
        "ns:m.0abc ns:r.one ?x .\n"
        "ns:m.0def ns:r.two ?x .\n"
    )
    assert category == "two_triples_not_dependent_chain"


def test_rejects_extra_constraint_triple():
    category, _ = classify(
        "ns:m.0abc ns:r.one ?y .\n"
        "?y ns:r.two ?x .\n"
        "?x ns:common.topic.notable_types ns:m.01y2hnl .\n"
    )
    # the grounded type constraint counts as a second anchor term
    assert category == "multi_anchor_join_3_triples"


def test_rejects_multi_anchor_tree():
    category, _ = classify(
        "?c ns:r.zero ns:m.0aaa .\n"
        "?c ns:r.one ?y .\n"
        "?y ns:r.two ?x .\n"
        "?y ns:r.three ns:m.0bbb .\n"
    )
    assert category == "multi_anchor_join_4_triples"


def test_rejects_order_by_limit():
    category, _ = extract_chain(parse_sparql(
        PREFIX + BOILER +
        "ns:m.0abc ns:r.one ?y .\n?y ns:r.two ?x .\n"
        "?x ns:time.event.start_date ?sk0 .\n"
        "}\nORDER BY DESC(xsd:datetime(?sk0))\nLIMIT 1\n"
    ))
    assert category == "order_limit_or_temporal"


def test_rejects_exists_temporal_block():
    category, _ = classify(
        "ns:m.0abc ns:r.one ?y .\n"
        "?y ns:r.two ?x .\n"
        "FILTER(NOT EXISTS {?y ns:r.from ?sk0} || \n"
        "EXISTS {?y ns:r.from ?sk1 . \n"
        "FILTER(xsd:datetime(?sk1) <= \"2015-08-10\"^^xsd:dateTime) })\n"
    )
    assert category == "order_limit_or_temporal"


def test_rejects_non_boilerplate_filter():
    category, _ = classify(
        "ns:m.0abc ns:r.one ?y .\n"
        "?y ns:r.two ?x .\n"
        "FILTER (?y != ns:m.0zzz)\n"
    )
    assert category == "unsupported_filter"


def test_rejects_manual_sparql():
    category, _ = extract_chain(parse_sparql(
        "#MANUAL SPARQL\n" + PREFIX +
        "ns:m.0abc ns:r.one ?y ;\n           ns:r.two ?x .\n}\n"
    ))
    assert category == "unparsed_manual_sparql"


def test_rejects_one_hop():
    category, _ = classify("ns:m.0abc ns:r.one ?x .\n")
    assert category == "one_hop"


def test_boilerplate_filters_do_not_reject():
    category, _ = classify(
        "ns:m.0abc ns:r.one ?y .\n?y ns:r.two ?x .\n", boiler=True
    )
    assert category == "strict_two_hop"


def rog_row(graph, q_entity):
    return {"graph": graph, "q_entity": q_entity, "answer": [], "a_entity": []}


def test_anchor_maps_mid_when_present():
    chain = {"anchor_mid": "m.0abc", "relation_1": "r.one", "relation_2": "r.two"}
    row = rog_row([["m.0abc", "r.one", "Mid"]], ["Anchor Name"])
    anchor, how = map_anchor(chain, row)
    assert anchor == "m.0abc" and how == "anchor_mid_in_graph"


def test_anchor_disambiguated_by_relation_1_orientation():
    chain = {"anchor_mid": "m.0abc",
             "relation_1": "r.one_inverse", "relation_2": "r.two"}
    row = rog_row(
        [["Mid", "r.one", "Right Anchor"], ["Wrong Anchor", "r.one", "Elsewhere"]],
        ["Right Anchor", "Wrong Anchor"],
    )
    anchor, how = map_anchor(chain, row)
    assert anchor == "Right Anchor"
    assert how == "unique_topic_entity_with_relation_1"


def test_anchor_ambiguous_is_rejected():
    chain = {"anchor_mid": "m.0abc", "relation_1": "r.one", "relation_2": "r.two"}
    row = rog_row(
        [["A", "r.one", "X"], ["B", "r.one", "Y"]],
        ["A", "B"],
    )
    anchor, how = map_anchor(chain, row)
    assert anchor is None
    assert how == "ambiguous_topic_entities_with_relation_1"


def test_single_topic_entity_without_edge_still_maps():
    chain = {"anchor_mid": "m.0abc", "relation_1": "r.one", "relation_2": "r.two"}
    row = rog_row([["Solo", "r.other", "X"]], ["Solo"])
    anchor, how = map_anchor(chain, row)
    assert anchor == "Solo"
    assert how == "single_topic_entity_without_relation_1_edge"
