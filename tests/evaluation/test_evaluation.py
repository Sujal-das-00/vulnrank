from scripts.run_evaluation import evaluate


def test_scenarios_all_pass():
    rows, fails, m = evaluate()
    assert not fails, "\n".join(fails)
    assert m["det"][0] == m["det"][1] and m["ids"][0] == m["ids"][1]
    assert len(rows) >= 30
