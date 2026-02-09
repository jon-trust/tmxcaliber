import json
from pathlib import Path

import pytest

from tmxcaliber.lib.threatmodel_data import (
    ThreatModelData,
    get_permissions,
    extract_threatmodel_reference_tokens,
)


def create_threatmodel(
    feature_classes=None, threats=None, controls=None, scorecard=None
):
    base_json = {
        "metadata": {"name": "Model"},
        "control_objectives": {},
        "actions": {},
    }
    base_json["threats"] = threats if threats is not None else {}
    base_json["controls"] = controls if controls is not None else {}
    base_json["feature_classes"] = (
        feature_classes if feature_classes is not None else {}
    )
    if scorecard is not None:
        base_json["scorecard"] = scorecard
    return ThreatModelData(base_json)


def reset_threatmodel_data_list():
    ThreatModelData.threatmodel_data_list = []


def test_feature_classes_not_fully_related():
    threatmodel_data = create_threatmodel(
        feature_classes={
            "FC1": {"class_relationship": [{"type": "parent", "class": "FC4"}]},
            "FC2": {"class_relationship": [{"type": "parent", "class": "FC1"}]},
            "FC3": {"class_relationship": []},
            "FC4": {"class_relationship": [{"type": "parent", "class": "FC3"}]},
            "FC5": {"class_relationship": [{"type": "parent", "class": "FC1"}]},
            "FC6": {
                "class_relationship": [
                    {"type": "parent", "class": "FC2"},
                    {"type": "parent", "class": "FC7"},
                ]
            },
            "FC7": {"class_relationship": []},
        }
    )
    not_fully_related_fc1 = threatmodel_data.get_feature_classes_not_fully_related(
        ["FC1"]
    )
    assert sorted(not_fully_related_fc1) == ["fc3", "fc4", "fc6", "fc7"]

    not_fully_related_fc2 = threatmodel_data.get_feature_classes_not_fully_related(
        ["FC2"]
    )
    assert sorted(not_fully_related_fc2) == ["fc1", "fc3", "fc4", "fc5", "fc6", "fc7"]

    not_fully_related_fc3 = threatmodel_data.get_feature_classes_not_fully_related(
        ["FC3"]
    )
    assert sorted(not_fully_related_fc3) == ["fc6", "fc7"]

    not_fully_related_fc6 = threatmodel_data.get_feature_classes_not_fully_related(
        ["FC6"]
    )
    assert sorted(not_fully_related_fc6) == ["fc1", "fc2", "fc3", "fc4", "fc5", "fc7"]

    fc1_ancestors = threatmodel_data.get_ancestors_feature_classes("FC1")
    assert sorted(fc1_ancestors) == ["fc3", "fc4"]

    fc1_ancestors = threatmodel_data.get_ancestors_feature_classes("FC6")
    assert sorted(fc1_ancestors) == ["fc1", "fc2", "fc3", "fc4", "fc7"]


def test_get_upstream_dependent_controls():
    threatmodel_data = create_threatmodel(
        controls={"service.c1": {"depends_on": "service.c2"}, "service.c2": {}}
    )
    assert threatmodel_data.get_upstream_dependent_controls("service.c1") == {
        "service.c2": {}
    }


def test_get_downstream_dependent_controls():
    threatmodel_data = create_threatmodel(
        controls={"service.c1": {"depends_on": "service.c2"}, "service.c2": {}}
    )
    assert threatmodel_data.get_downstream_dependent_controls(["service.c2"]) == {
        "service.c1"
    }


def example_threatmodel_json():
    return {
        "metadata": {"name": "Model"},
        "threats": {
            "1": {
                "example_threat": "data",
                "mitigate": [{"threat": "1"}, {"threat": "2"}],
            },
            "2": {"example_threat": "data", "mitigate": [{"threat": "1"}]},
        },
        "feature_classes": {
            "FC1": {"example_feature_class": "data"},
            "FC2": {"example_feature_class": "data"},
        },
        "controls": {
            "control1": {
                "feature_class": ["FC1"],
                "mitigate": [{"threat": "1"}],
                "assured_by": "control2",
            },
            "control2": {
                "feature_class": ["FC2"],
                "mitigate": [{"threat": "2"}],
                "assured_by": "",
            },
        },
        "control_objectives": {},
        "actions": {},
    }


def test_get_controls_for_current_threats():
    threatmodel_data = create_threatmodel(
        feature_classes={
            "FC1": {"class_relationship": []},
            "FC2": {"class_relationship": []},
        },
        threats={"T1": {}, "T2": {}},
        controls={
            "control1": {
                "feature_class": ["FC1"],
                "mitigate": [{"threat": "T1"}],
                "assured_by": "control2",
            },
            "control2": {"feature_class": ["FC1"], "mitigate": [], "assured_by": ""},
            "control3": {
                "feature_class": ["FC3"],
                "mitigate": [{"threat": "T2"}],
                "assured_by": "",
            },
            "control4": {
                "feature_class": ["FC1"],
                "mitigate": [{"threat": "T3"}],
                "assured_by": "",
            },
            "control5": {
                "feature_class": ["FC2"],
                "mitigate": [{"threat": "T2"}],
                "assured_by": "",
            },
        },
    )

    controls = threatmodel_data.get_controls_for_current_threats()

    assert controls == {
        "control1": {
            "feature_class": ["FC1"],
            "mitigate": [{"threat": "T1"}],
            "assured_by": "control2",
        },
        "control2": {"feature_class": ["FC1"], "mitigate": [], "assured_by": ""},
        "control5": {
            "feature_class": ["FC2"],
            "mitigate": [{"threat": "T2"}],
            "assured_by": "",
        },
    }


def test_get_permissions():
    access_data = {
        "AND": ["read_data", {"OPTIONAL": ["optional_read"]}],
        "UNIQUE": "write_data",
        "OPTIONAL": ["optional_write"],
    }

    # Test with add_optional=True
    permissions_with_optional = get_permissions(access_data, add_optional=True)
    assert sorted(permissions_with_optional) == [
        "optional_read",
        "optional_write",
        "read_data",
        "write_data",
    ]

    # Test with add_optional=False
    permissions_without_optional = get_permissions(access_data, add_optional=False)
    assert sorted(permissions_without_optional) == ["read_data", "write_data"]


def test_get_csv_of_aws_data_perimeter_controls_basic_extraction():
    reset_threatmodel_data_list()
    create_threatmodel(
        scorecard={
            "aws_data_perimeter": {
                "Perimeter": ["Service.C1", "Service.C2"],
                "NA": ["Service.C999"],
            }
        }
    )

    csv_matrix = ThreatModelData.get_csv_of_aws_data_perimeter_controls()

    assert csv_matrix == [["id"], ["Service.C1"], ["Service.C2"]]


def test_get_csv_of_aws_data_perimeter_controls_deduplication():
    reset_threatmodel_data_list()
    create_threatmodel(
        scorecard={
            "aws_data_perimeter": {
                "CategoryA": ["Service.C1", "Service.C2"],
                "CategoryB": ["Service.C2"],
            }
        }
    )

    csv_matrix = ThreatModelData.get_csv_of_aws_data_perimeter_controls()

    assert csv_matrix == [["id"], ["Service.C1"], ["Service.C2"]]


def test_get_csv_of_aws_data_perimeter_controls_missing_scorecard():
    reset_threatmodel_data_list()
    create_threatmodel()

    csv_matrix = ThreatModelData.get_csv_of_aws_data_perimeter_controls()

    assert csv_matrix == [["id"]]


def test_get_csv_of_aws_data_perimeter_controls_directory_aggregation():
    reset_threatmodel_data_list()
    create_threatmodel(
        scorecard={
            "aws_data_perimeter": {
                "CategoryA": ["Service.C1", "Service.C3"],
                "NA": ["Service.C999"],
            }
        }
    )
    create_threatmodel(
        scorecard={
            "aws_data_perimeter": {
                "CategoryB": ["Service.C2", "Service.C3"],
            }
        }
    )

    csv_matrix = ThreatModelData.get_csv_of_aws_data_perimeter_controls()

    assert csv_matrix == [
        ["id"],
        ["Service.C1"],
        ["Service.C2"],
        ["Service.C3"],
    ]


def test_get_csv_of_aws_data_perimeter_controls_case_insensitive_na():
    reset_threatmodel_data_list()
    create_threatmodel(
        scorecard={
            "aws_data_perimeter": {
                " na ": ["Service.C1"],
                "NA": ["Service.C2"],
                "CategoryA": ["Service.C3"],
            }
        }
    )

    csv_matrix = ThreatModelData.get_csv_of_aws_data_perimeter_controls()

    assert csv_matrix == [["id"], ["Service.C3"]]


def test_extract_threatmodel_reference_tokens_multiple_patterns():
    assert extract_threatmodel_reference_tokens(
        "This control is implemented using IAM ThreatModel and Route53 ThreatModel."
    ) == ["iam", "route53"]

    assert extract_threatmodel_reference_tokens(
        "This control is implemented using IAM and Route53 ThreatModels."
    ) == ["route53", "iam"]


def test_get_csv_of_aws_data_perimeter_controls_extended_missing_alias_logs_and_continues(
    tmp_path: Path,
):
    reset_threatmodel_data_list()

    create_threatmodel(
        controls={
            "Service.C1": {
                "description": "Implemented using IAM ThreatModel.",
                "objective": "",
                "retired": "",
            }
        },
        scorecard={"aws_data_perimeter": {"CategoryA": ["Service.C1"]}},
    )

    csv_matrix = ThreatModelData.get_csv_of_aws_data_perimeter_controls_extended(
        threatmodel_dir=str(tmp_path),
        alias_map={},
    )

    ids = [row[csv_matrix[0].index("id")] for row in csv_matrix[1:]]
    assert ids == ["Service.C1"]


def test_get_csv_of_aws_data_perimeter_controls_extended_alias_points_to_missing_tm_raises(
    tmp_path: Path,
):
    reset_threatmodel_data_list()

    create_threatmodel(
        controls={
            "Service.C1": {
                "description": "Implemented using IAM ThreatModel.",
                "objective": "",
                "retired": "",
            }
        },
        scorecard={"aws_data_perimeter": {"CategoryA": ["Service.C1"]}},
    )

    with pytest.raises(ValueError, match="was found in --threatmodel-dir"):
        ThreatModelData.get_csv_of_aws_data_perimeter_controls_extended(
            threatmodel_dir=str(tmp_path),
            alias_map={"iam": "aws-iam"},
        )


def test_get_csv_of_aws_data_perimeter_controls_extended_happy_path(tmp_path: Path):
    reset_threatmodel_data_list()

    create_threatmodel(
        controls={
            "Service.C1": {
                "description": "Implemented using IAM ThreatModel.",
                "objective": "",
                "retired": "",
            },
            "Service.C2": {
                "description": "Some other control.",
                "objective": "",
                "retired": "",
            },
        },
        scorecard={"aws_data_perimeter": {"CategoryA": ["Service.C1"]}},
    )

    ref_json = {
        "metadata": {"name": "IAM", "provider": "aws", "service": "iam"},
        "threats": {},
        "feature_classes": {},
        "controls": {
            "Service.C2": {
                "description": "Referenced control",
                "objective": "",
                "retired": "",
            }
        },
        "control_objectives": {},
        "actions": {},
        "scorecard": {"aws_data_perimeter": {"CategoryX": ["Service.C2"]}},
    }
    (tmp_path / "aws_iam.json").write_text(json.dumps(ref_json), encoding="utf-8")

    csv_matrix = ThreatModelData.get_csv_of_aws_data_perimeter_controls_extended(
        threatmodel_dir=str(tmp_path),
        alias_map={"iam": "aws-iam"},
    )

    ids = [row[csv_matrix[0].index("id")] for row in csv_matrix[1:]]
    assert sorted(ids) == ["Service.C1", "Service.C2"]
