import json
from unittest.mock import patch, MagicMock
import pytest
import src.main as main


def test_sort_controls():
    controls = main.ControlsLocal(
        controls={
            "cis-aws-foundations-benchmark": {
                "CIS.1.1": {},
                "CIS.1.2": {},
                "CIS.1.10": {},
            },
            "aws-foundational-security-best-practices": {
                "RDS.1": {},
                "RDS.10": {},
                "RDS.2": {},
            },
        }
    )
    controls.sort_controls()
    assert controls.controls["cis-aws-foundations-benchmark"] == {
        "CIS.1.1": {},
        "CIS.1.10": {},
        "CIS.1.2": {},
    }
    assert controls.controls["aws-foundational-security-best-practices"] == {
        "RDS.1": {},
        "RDS.2": {},
        "RDS.10": {},
    }


def test_exception_exists():
    controls = main.ControlsLocal(
        controls={
            "cis-aws-foundations-benchmark": {
                "CIS.1.1": {},
                "CIS.1.2": {"Enabled": ["1"]},
                "CIS.1.3": {"Disabled": ["1"]},
            }
        }
    )
    assert not controls.exception_exists("CIS.1.1")
    assert controls.exception_exists("CIS.1.2")
    assert controls.exception_exists("CIS.1.3")


@patch("src.main.boto3")
def test_updated_standards_online(boto3):
    client = boto3.client("securityhub")
    controls_local_cis = main.ControlsLocal(
        controls={"cis-aws-foundations-benchmark": {"CIS.1.1", "CIS.1.2", "CIS.1.10"}}
    )
    controls_local_empty = main.ControlsLocal()
    controls_online_cis = {
        "cis-aws-foundations-benchmark": {
            "Controls": [
                {
                    "StandardsControlArn": "arn:aws:securityhub:eu-central-1:724965535027:control/cis-aws-foundations-benchmark/v/1.2.0/1.1",
                    "ControlStatus": "ENABLED",
                    "ControlId": "CIS.1.1",
                    "Title": 'Avoid the use of the "root" account',
                    "Description": 'The "root" account has unrestricted access to all resources in the AWS account. It is highly recommended that the use of this account be avoided.',
                },
                {
                    "StandardsControlArn": "arn:aws:securityhub:eu-central-1:724965535027:control/cis-aws-foundations-benchmark/v/1.2.0/1.10",
                    "ControlStatus": "ENABLED",
                    "ControlId": "CIS.1.10",
                    "Title": "Ensure IAM password policy prevents password reuse",
                    "Description": "IAM password policies can prevent the reuse of a given password by the same user. It is recommended that the password policy prevent the reuse of passwords.",
                },
                {
                    "StandardsControlArn": "arn:aws:securityhub:eu-central-1:724965535027:control/cis-aws-foundations-benchmark/v/1.2.0/1.2",
                    "ControlStatus": "ENABLED",
                    "ControlId": "CIS.1.2",
                    "Title": "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
                    "Description": "Multi-Factor Authentication (MFA) adds an extra layer of protection on top of a user name and password. It is recommended that MFA be enabled for all accounts that have a console password.",
                },
            ]
        }
    }
    controls_online_empty = dict()
    client.describe_standards.return_value = {
        "Standards": [
            {
                "StandardsArn": "arn:aws:securityhub:eu-central-1::standards/aws-foundational-security-best-practices/v/1.0.0",
                "Name": "AWS Foundational Security Best Practices v1.0.0",
                "Description": "The AWS Foundational Security Best Practices standard is a set of automated security checks that detect when AWS accounts and deployed resources do not align to security best practices. The standard is defined by AWS security experts. This curated set of controls helps improve your security posture in AWS, and cover AWS’s most popular and foundational services.",
                "EnabledByDefault": True,
            },
            {
                "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
                "Name": "CIS AWS Foundations Benchmark v1.2.0",
                "Description": "The Center for Internet Security (CIS) AWS Foundations Benchmark v1.2.0 is a set of security configuration best practices for AWS. This Security Hub standard automatically checks for your compliance readiness against a subset of CIS requirements.",
                "EnabledByDefault": True,
            },
            {
                "StandardsArn": "arn:aws:securityhub:eu-central-1::standards/pci-dss/v/3.2.1",
                "Name": "PCI DSS v3.2.1",
                "Description": "The Payment Card Industry Data Security Standard (PCI DSS) v3.2.1 is an information security standard for entities that store, process, and/or transmit cardholder data. This Security Hub standard automatically checks for your compliance readiness against a subset of PCI DSS requirements.",
                "EnabledByDefault": False,
            },
        ]
    }
    client.get_enabled_standards.return_value = {
        "StandardsSubscriptions": [
            {"StandardsArn": "AFSBP", "StandardsStatus": "READY"},
            {"StandardsArn": "cis", "StandardsStatus": "READY"},
            {"StandardsArn": "pci-dss", "StandardsStatus": "INCOMPLETE"},
        ]
    }
    assert not main.update_standards_online(
        client, controls_local_empty, controls_online_empty
    )
    assert main.update_standards_online(
        client, controls_local_empty, controls_online_cis
    )
    assert main.update_standards_online(
        client, controls_local_cis, controls_online_empty
    )
    assert not main.update_standards_online(
        client, controls_local_cis, controls_online_cis
    )
    client.get_enabled_standards.return_value = {
        "StandardsSubscriptions": [
            {"StandardsArn": "AFSBP", "StandardsStatus": "FAILED"},
            {"StandardsArn": "cis", "StandardsStatus": "READY"},
            {"StandardsArn": "pci-dss", "StandardsStatus": "INCOMPLETE"},
        ]
    }
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        main.update_standards_online(client, controls_local_empty, controls_online_cis)
    assert pytest_wrapped_e.type == SystemExit
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        main.update_standards_online(client, controls_local_cis, controls_online_empty)
    assert pytest_wrapped_e.type == SystemExit


def test_convert_exceptions():
    dynamodb_response = json.loads(
        '{"Items": [{"ControlId": {"S": "CIS.1.1"}, "Disabled": {"L": [{"S": "111111111111"}]}, "Enabled": {"L": []}, "DisabledReason": {"S": "Some_Reason"}}, {"Disabled": {"L": []}, "ControlId": {"S": "CIS.1.2"}, "Enabled": {"L": [{"S": "22222222222"}]}}, {"Disabled": {"L": [{"S": "111111111111"}]}, "ControlId": {"S": "CIS.1.4"}}, {"ControlId": {"S": "CIS.1.3"}, "Enabled": {"L": [{"S": "22222222222"}]}, "DisabledReason": {"S": ""}}, {"ControlId": {"S": "CIS.1.5"}}]}'
    )
    expected_response = {
        "CIS.1.1": {
            "Disabled": ["111111111111"],
            "Enabled": [],
            "DisabledReason": "Some_Reason",
        },
        "CIS.1.2": {
            "Disabled": [],
            "Enabled": ["22222222222"],
            "DisabledReason": main.DISABLED_REASON_EXCEPTION,
        },
        "CIS.1.3": {
            "Disabled": [],
            "Enabled": ["22222222222"],
            "DisabledReason": main.DISABLED_REASON_EXCEPTION,
        },
        "CIS.1.4": {
            "Disabled": ["111111111111"],
            "Enabled": [],
            "DisabledReason": main.DISABLED_REASON_EXCEPTION,
        },
        "CIS.1.5": {
            "Disabled": [],
            "Enabled": [],
            "DisabledReason": main.DISABLED_REASON_EXCEPTION,
        },
    }
    response = main.convert_exceptions(dynamodb_response)
    assert expected_response == response


def test_add_control_exception_disabled_reason_from_online():
    exception = {
        "Disabled": ["111111111111"],
        "Enabled": [],
        "DisabledReason": "Some_Reason",
    }
    controls = main.ControlsLocal(
        controls={"cis-aws-foundations-benchmark": {"CIS.1.1": {"DisabledReason": ""}}}
    )
    control = {
        "StandardsControlArn": "arn:aws:securityhub:eu-central-1:724965535027:control/cis-aws-foundations-benchmark/v/1.2.0/1.1",
        "ControlId": "CIS.1.1",
    }
    controls.add_control_exception(control, exception)
    assert controls.controls["cis-aws-foundations-benchmark"] == {
        "CIS.1.1": {"Disabled": ["111111111111"], "DisabledReason": "Some_Reason"}
    }


def test_add_control_exception_disabled_reason_from_local():
    exception = {
        "Disabled": ["111111111111"],
        "Enabled": [],
        "DisabledReason": "Some_Reason",
    }
    controls = main.ControlsLocal(
        controls={
            "cis-aws-foundations-benchmark": {
                "CIS.1.1": {"DisabledReason": "LocalReason"}
            }
        }
    )
    control = {
        "StandardsControlArn": "arn:aws:securityhub:eu-central-1:724965535027:control/cis-aws-foundations-benchmark/v/1.2.0/1.1",
        "ControlId": "CIS.1.1",
    }
    controls.add_control_exception(control, exception)
    assert controls.controls["cis-aws-foundations-benchmark"] == {
        "CIS.1.1": {"Disabled": ["111111111111"], "DisabledReason": "LocalReason"}
    }


def test_add_control_exception_enabled():
    exception = {
        "Disabled": [],
        "Enabled": ["111111111111"],
        "DisabledReason": "Some_Reason",
    }
    controls = main.ControlsLocal(
        controls={
            "cis-aws-foundations-benchmark": {
                "CIS.1.1": {"DisabledReason": "LocalReason"}
            }
        }
    )
    control = {
        "StandardsControlArn": "arn:aws:securityhub:eu-central-1:724965535027:control/cis-aws-foundations-benchmark/v/1.2.0/1.1",
        "ControlId": "CIS.1.1",
    }
    controls.add_control_exception(control, exception)
    assert controls.controls["cis-aws-foundations-benchmark"] == {
        "CIS.1.1": {"Enabled": ["111111111111"], "DisabledReason": "LocalReason"}
    }


@patch("src.main.make_item")
def test_update_exceptions(make_item):
    client = MagicMock()
    dynamodb = "TableName"
    controls = main.ControlsLocal(
        controls={
            "cis-aws-foundations-benchmark": {
                "CIS.1.1": {"DisabledReason": "LocalReason", "Enabled": ["1"]},
                "CIS.1.2": {"DisabledReason": "LocalReason", "Disabled": ["1"]},
                "CIS.1.3": {"DisabledReason": "LocalReason"},
                "CIS.1.4": {"Disabled": ["2"]},
                "CIS.1.5": {},
            }
        }
    )
    exceptions_online = {
        "CIS.1.1": {"Disabled": ["1"], "Enabled": [], "DisabledReason": "Some_Reason"},
        "CIS.1.4": {"Disabled": ["2"]},
        "CIS.1.5": {},
    }
    with patch.object(main, "get_exceptions_online", return_value=exceptions_online):
        main.update_exceptions(controls, client, dynamodb)
    assert client.put_item.call_count == 2
    assert client.delete_item.call_count == 1


def test_make_item():
    local_control_all = {
        "Enabled": [1],
        "Disabled": [2],
        "DisabledReason": "SomeReason",
    }
    local_control_no_disabled = {"Enabled": ["1"], "DisabledReason": "SomeReason"}
    local_control_no_enabled = {"Disabled": ["2"], "DisabledReason": "SomeReason"}
    local_control_no_disabled_reason = {
        "Enabled": ["1"],
        "Disabled": ["2"],
        "DisabledReason": "",
    }

    control = "CIS.1.1"

    item = main.make_item(control, local_control_all)
    expected_item = {
        "Disabled": {"L": [{"S": "2"}]},
        "Enabled": {"L": [{"S": "1"}]},
        "DisabledReason": {"S": local_control_all["DisabledReason"]},
        "ControlId": {"S": control},
    }
    assert item == expected_item

    item = main.make_item(control, local_control_no_disabled)
    expected_item = {
        "Enabled": {
            "L": [{"S": str(acc_id) for acc_id in local_control_no_disabled["Enabled"]}]
        },
        "ControlId": {"S": control},
    }
    assert item == expected_item

    item = main.make_item(control, local_control_no_enabled)
    expected_item = {
        "Disabled": {
            "L": [{"S": str(acc_id) for acc_id in local_control_no_enabled["Disabled"]}]
        },
        "DisabledReason": {"S": local_control_no_enabled["DisabledReason"]},
        "ControlId": {"S": control},
    }
    assert item == expected_item

    item = main.make_item(control, local_control_no_disabled_reason)
    expected_item = {
        "Enabled": {
            "L": [
                {
                    "S": str(acc_id)
                    for acc_id in local_control_no_disabled_reason["Enabled"]
                }
            ]
        },
        "Disabled": {
            "L": [
                {
                    "S": str(acc_id)
                    for acc_id in local_control_no_disabled_reason["Disabled"]
                }
            ]
        },
        "DisabledReason": {"S": main.DISABLED_REASON_EXCEPTION},
        "ControlId": {"S": control},
    }
    assert item == expected_item

    item = main.make_item(control, local_control_all)
    expected_item = {
        "Disabled": {"L": [{"S": "2"}]},
        "Enabled": {"L": [{"S": "1"}]},
        "DisabledReason": {"S": local_control_all["DisabledReason"]},
        "ControlId": {"S": control},
    }
    assert item == expected_item


def test_exceptions_match():
    exceptions_none = {}
    exceptions_disabled = {"Disabled": ["1"]}
    exceptions_disabled_reason = {"Disabled": ["1"], "DisabledReason": "Some_Reason"}
    exceptions_enabled = {"Enabled": ["1"]}
    exceptions_enabled_disabled_empty = {"Enabled": ["1"], "Disabled": []}
    exceptions_disabled_enabled_empty = {
        "Enabled": [],
        "Disabled": ["1"],
        "DisabledReason": "Some_Reason",
    }
    exceptions_disabled_reason_exception = {
        "Disabled": ["1"],
        "DisabledReason": main.DISABLED_REASON_EXCEPTION,
    }

    local_none = {"DisabledReason": "LocalReason"}
    local_enabled = {"DisabledReason": "LocalReason", "Enabled": [1]}
    local_enabled_other_account = {"DisabledReason": "LocalReason", "Enabled": [2]}
    local_disabled_false_reason = {"DisabledReason": "LocalReason", "Disabled": [1]}
    local_disabled_matched_reason = {"DisabledReason": "Some_Reason", "Disabled": [1]}
    local_no_list = {"DisabledReason": "Some_Reason", "Disabled": "String"}
    local_no_string = {"DisabledReason": 123, "Disabled": [1]}
    local_disabled_no_reason = {"DisabledReason": "", "Disabled": [1]}

    assert main.exceptions_match(exceptions_none, local_none)
    assert not main.exceptions_match(exceptions_disabled, local_none)
    assert not main.exceptions_match(exceptions_disabled, local_enabled)
    assert not main.exceptions_match(exceptions_disabled, local_disabled_false_reason)
    assert not main.exceptions_match(
        exceptions_disabled_reason, local_disabled_false_reason
    )
    assert main.exceptions_match(
        exceptions_disabled_reason, local_disabled_matched_reason
    )
    assert main.exceptions_match(
        exceptions_disabled_enabled_empty, local_disabled_matched_reason
    )
    assert not main.exceptions_match(exceptions_enabled, local_none)
    assert not main.exceptions_match(exceptions_enabled, local_disabled_matched_reason)
    assert main.exceptions_match(exceptions_enabled_disabled_empty, local_enabled)
    assert main.exceptions_match(exceptions_enabled, local_enabled)
    assert not main.exceptions_match(exceptions_enabled, local_enabled_other_account)
    assert main.exceptions_match(exceptions_disabled_reason_exception, local_disabled_no_reason)

    # Sanity checks
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        main.exceptions_match(exceptions_enabled, local_no_list)
    assert pytest_wrapped_e.type == SystemExit
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        main.exceptions_match(exceptions_disabled, local_no_string)
    assert pytest_wrapped_e.type == SystemExit
