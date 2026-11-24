import json

from zeroflaw.report import save_report


def test_save_report_writes_json_into_the_folder(tmp_path):
    data = {"target": "snippets", "findings": []}
    path = save_report(data, tmp_path / "snippets", out_dir=tmp_path / "reports")
    assert path.parent == tmp_path / "reports"
    assert path.suffix == ".json"
    assert json.loads(path.read_text()) == data


def test_two_saves_do_not_overwrite_each_other(tmp_path):
    first = save_report({}, tmp_path / "x", out_dir=tmp_path)
    second = save_report({}, tmp_path / "x", out_dir=tmp_path)
    assert first != second