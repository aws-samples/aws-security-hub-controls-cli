# Security Hub Controls CLI

A CLI tool to disable and enable security standards controls in AWS Security Hub.

## Purpose

The goal of this tool is to provide a possibility to maintain the status (`DISABLED` or `ENABLED`) of standards controls in AWS Security Hub within a file. That way, the status can be configured by using a code repository and a CICD pipeline.

## Install

This tool can be install using pip:
```
git clone https://github.com/aws-samples/aws-security-hub-controls-cli/
pip install ./aws-security-hub-controls-cli
```

## Usage
```
usage: shc_cli [-h] [-d] [-u UPLOAD] [--json] [--profile PROFILE]
               [--dynamodb DYNAMODB] [--max-retries MAX_RETRIES] [-v]

Disable or Enable security standards controls in AWS Security Hub.

optional arguments:
  -h, --help            show this help message and exit
  -d, --download        Get current controls configurations from Security Hub.
  -u UPLOAD, --upload UPLOAD
                        Upload Security Hub controls configurations as defined
                        in UPLOAD file.
  --json                Use json as file format (instead of yaml) when
                        downloading current controls configurations from
                        Security Hub. Only effective when used in conjunction
                        with -d/--download
  --profile PROFILE     Use a specific profile from your credential file.
  --dynamodb DYNAMODB   Optional - Specify DynamoDB table name storing exceptions.
  --max-retries MAX_RETRIES
                        Maximal amount of retries in case of a
                        TooManyRequestsException when updating Security Hub
                        controls. (default: infinity)
  -v, --verbosity       Debugging information
```

## Prerequisites
AWS Security Hub and [security standards](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html) must be enabled.

You need following permissions to use this tool to update controls and security standards in Security Hub:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "securityhub:GetEnabledStandards",
                "securityhub:DescribeStandardsControls",
                "securityhub:UpdateStandardsControl"
            ],
            "Resource": "*"
        }
    ]
}
```
To use the `--dynamodb` option for storing exceptions in AWS DynamoDB, you need a DynamoDB table in the same AWS account as the Security Hub instance updated by the tool. A template which generates the needed DynamoDB table can be found [here](dynamodb_template.yaml). Additionally to that, the following permissions are needed:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:Scan",
                "dynamodb:PutItem"
            ],
            "Resource": <DynamoDBArn>
        }
    ]
}
```


## Workflow and examples

This section describes some basic use-cases and workflows

### Getting current controls and initializing the local file

To get the current control statuses from Security Hub, use the following command:
```
$ shd_cli -d
cis-aws-foundations-benchmark:
  CIS.1.1:
    Title: Avoid the use of the "root" account
    ControlStatus: ENABLED
    DisabledReason: ''
  CIS.1.2:
    Title: Ensure multi-factor authentication (MFA) is enabled for all IAM users that
      have a console password
    ControlStatus: ENABLED
    DisabledReason: ''
...
```
If you prefer JSON over yaml, use the `--json` option:
```
$ shd_cli -d --json
{
    "cis-aws-foundations-benchmark": {
        "CIS.1.1": {
            "Title": "Avoid the use of the \"root\" account",
            "ControlStatus": "ENABLED",
            "DisabledReason": ""
        },
        "CIS.1.2": {
            "Title": "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
            "ControlStatus": "ENABLED",
            "DisabledReason": ""
        },
...
```
You can write the output into a local file:
```
$ shd_cli -d > controls.yaml
$ cat controls.yaml
cis-aws-foundations-benchmark:
  CIS.1.1:
    Title: Avoid the use of the "root" account
    ControlStatus: ENABLED
    DisabledReason: ''
  CIS.1.2:
    Title: Ensure multi-factor authentication (MFA) is enabled for all IAM users that
      have a console password
    ControlStatus: ENABLED
    DisabledReason: ''
...
```

### Update Security Hub controls as defined in local file

The local file can be used to edit the `ControlStatus` of single controls.  
**If you do not provide a `DisabledReason`, the default *Updated via CLI* is used.**  
Let's disable controls CIS.1.1 and CIS.1.2. We provide a `DisabledReason` for CIS.1.1:
```
$ cat controls.yaml
cis-aws-foundations-benchmark:
  CIS.1.1:
    Title: Avoid the use of the "root" account
    ControlStatus: DISABLED
    DisabledReason: 'Risk accepted by Security Department'
  CIS.1.2:
    Title: Ensure multi-factor authentication (MFA) is enabled for all IAM users that
      have a console password
    ControlStatus: DISABLED
    DisabledReason: ''
...
```
Now, let's update the controls in Security Hub:
```
$ shc_cli -u controls.yaml
Start updating security standard controls...
CIS.1.1 : Update to DISABLED
CIS.1.1 : Done
CIS.1.2 : Update to DISABLED
CIS.1.2 : Done
Security standard controls updated.
Start updating security standard controls...
Security standard controls updated.
```
These are the new statuses of the security standard controls:
```
$ shc_cli -d
cis-aws-foundations-benchmark:
  CIS.1.1:
    Title: Avoid the use of the "root" account
    ControlStatus: DISABLED
    DisabledReason: Risk accepted by Security Department
  CIS.1.2:
    Title: Ensure multi-factor authentication (MFA) is enabled for all IAM users that
      have a console password
    ControlStatus: DISABLED
    DisabledReason: Updated via CLI
...
```

### New security standard or control added to Security Hub

In the case of activating a new security standard or AWS adding a new control to an existing standard, this tool will update the local file accordingly.  
Let's simulate this situation by removing the `CIS.1.1` control from the local file:
```
$ cat controls.yaml
cis-aws-foundations-benchmark:
  CIS.1.2:
    Title: Ensure multi-factor authentication (MFA) is enabled for all IAM users that
      have a console password
    ControlStatus: DISABLED
    DisabledReason: Updated via CLI
  CIS.1.3:
    Title: Ensure credentials unused for 90 days or greater are disabled
    ControlStatus: ENABLED
    DisabledReason: ''
...
```
When the controls are now updated with this tool, you receive an information that a new control was discovered and the local file has been updated:
```
$ shc_cli -u controls.yaml
Start updating security standard controls...
[WARNING] Control cis-aws-foundations-benchmark:CIS.1.1 does not exist in local file. Local file is being updated ...
Security standard controls updated.
Start updating security standard controls...
Security standard controls updated.

$ cat controls.yaml
cis-aws-foundations-benchmark:
  CIS.1.1:
    Title: Avoid the use of the "root" account
    ControlStatus: DISABLED
    DisabledReason: 'Risk accepted by Security Department'
  CIS.1.2:
    Title: Ensure multi-factor authentication (MFA) is enabled for all IAM users that
      have a console password
    ControlStatus: DISABLED
    DisabledReason: ''
...
```

### Adding an exception for individual accounts

If you specify a DynamoDB table with the `--dynamodb` option, you can define exceptional disable/enable actions for individual accounts. This will save the information in the DynamoDB table. The needed action of actually processing the information and enabling/disabling the controls for the specified accounts needs to implemented seperatly.  
As a prerequisite, an according DynamoDB table must be present in the same AWS account as the Security Hub instance updated by the tool. A template which generates the needed DynamoDB table can be found [here](dynamodb_template.yaml).

Exceptions are defined as a list of account IDs in the optional `Enabled` and `Disabled` fields per control, as seen in the following example.
```
$ cat controls.yaml
cis-aws-foundations-benchmark:
  CIS.1.1:
    Title: Avoid the use of the "root" account
    ControlStatus: DISABLED
    DisabledReason: 'Risk accepted by Security Department'
    Enabled:
      - 111111111111
  CIS.1.2:
    Title: Ensure multi-factor authentication (MFA) is enabled for all IAM users that
      have a console password
    ControlStatus: ENABLED
    DisabledReason: ''
    Disabled:
      - 222222222222
...
```
If no `DisabledReason` is specified, as for `CIS.1.2` above, *Exception* will be used as a default `DisabledReason` in the DynamoDB table.  
When the controls are now updated with this tool, you receive an information that the exceptions will be created (or updated) in the DynamoDB table.
```
$ shc_cli -u controls.yaml --dynamodb DYNAMODB_TABLENAME
Start updating security standard controls...
CIS.1.1 : Update to DISABLED
CIS.1.1 : Done
CIS.1.2 : Update to ENABLED
CIS.1.2 : Done
Security standard controls updated.
Start updating exceptions in DynamoDB table...
CIS.1.1: Create exceptions in DynamoDB table.
CIS.1.2: Create exceptions in DynamoDB table.
Exceptions in DynamoDB table updated.
```
When you now download the control statuses by providing the DynamoDB table name, you will receive the exceptions as well:
```
$ shc_cli -d --dynamodb DYNAMODB_TABLENAME
cis-aws-foundations-benchmark:
  CIS.1.1:
    Title: Avoid the use of the "root" account
    ControlStatus: DISABLED
    DisabledReason: Risk accepted by Security Department
    Enabled:
    - '111111111111'
  CIS.1.2:
    Title: Ensure multi-factor authentication (MFA) is enabled for all IAM users that
      have a console password
    ControlStatus: ENABLED
    DisabledReason: Exception
    Disabled:
    - '22222222222'
...
```
