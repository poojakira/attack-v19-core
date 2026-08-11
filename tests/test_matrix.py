from attack_core.matrix import ATTACKMatrix


def test_html_output_escapes_stix_controlled_fields(monkeypatch):
    matrix = ATTACKMatrix(index=None)  # type: ignore[arg-type]
    source = {
        "domain": "enterprise",
        "tactics": [
            {
                "tactic_id": "TA0001",
                "tactic_name": '<script id="tactic">alert(1)</script>',
                "techniques": [
                    {
                        "technique_id": "T0001",
                        "technique_name": '<img src=x onerror="alert(2)">',
                        "subtechniques": [
                            {
                                "subtechnique_id": "T0001.001",
                                "subtechnique_name": "A & B",
                            }
                        ],
                    }
                ],
            }
        ],
    }
    monkeypatch.setattr(matrix, "to_dict", lambda _domain: source)

    rendered = matrix.to_html()

    assert "<script" not in rendered
    assert "<img" not in rendered
    assert "&lt;script" in rendered
    assert "&lt;img" in rendered
    assert "A &amp; B" in rendered
