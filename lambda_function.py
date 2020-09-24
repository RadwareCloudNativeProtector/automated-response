'''
For Alert: This example includes the extraction of Radware's CWP json Alert from SNS,
    extraction of relevant AWS resources that could have been compromised
    and the responses available in order to stop any malicious operations by those resources.
    For compromised users we can respond by blocking his console login (delete login profile),
    by blocking his cli key (deactivate access key) or 'suspend' his activity by
    setting deny permission boundary to make all methods unavailable for the user.
    For compromised roles and instances we can respond by disassociating the role
    from instance (to prevent future attempts to use the machine for malicious actions
    with the permissions of the role) and revoke the role with deny permission to
    interrupt any ongoing assuming of the role, or quarantine the instance by attaching it
    a security group which will prevent any inbound and outbound traffic and reboot
    the instance to interrupt any current connection to it, or simply stop the instance.
    For compromised databases we can respond by preventing all access to the database
    by attaching it a security group which will prevent any inbound and outbound traffic
    and reboot the database to interrupt any current connection to it.
    For cloudtrail logs, if a trail was stopped, we can re-start it.
    For S3 buckets, if a bucket was made publicly accessed, we can block it.

For Hardening: This example includes the extraction of Radware's CWP json Hardening Warning (Misconfiguration, Exposed Machines, Exposed Database) from SNS,
    extraction of relevant AWS resources that failed to pass misconfiguration rules or that are exposed
    and the responses available in order to avoid option of attackers to take advantage of these vulnerabilities.
    For users with console login and no MFA configured we can respond by blocking his console login (delete login profile).
    For users with unused credentials we can respond by blocking his cli key (deactivate access key).
    For exposed machines and databases we can remove the inbound rule that is the reason for the exposure.


Required IAM Policy permissions:
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "RadwarCWPAutomatedResponse",
            "Effect": "Allow",
            "Action": [
                "iam:UpdateAccessKey",
                "iam:DeleteLoginProfile",
                "iam:ListAccessKeys",
                "iam:PutUserPermissionsBoundary",
                "iam:DeleteUserPermissionsBoundary",
                "iam:PutRolePolicy",
                "iam:GetPolicy",
                "iam:CreatePolicy",
                "iam:GetUser",
                "ec2:DisassociateIamInstanceProfile",
                "ec2:RebootInstances",
                "ec2:DescribeIamInstanceProfileAssociations",
                "ec2:ModifyInstanceAttribute",
                "ec2:StopInstances",
                "ec2:CreateSecurityGroup",
                "ec2:DescribeSecurityGroups",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:RevokeSecurityGroupIngress",
                "rds:ModifyDBInstance",
                "rds:RebootDBInstance",
                "rds:DescribeDBInstances",
                "rds:RevokeDBSecurityGroupIngress",
                "cloudtrail:StartLogging",
                "s3:PutBucketPublicAccessBlock",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "sts:AssumeRole"
            ],
            "Resource": "*"
        }
    ]
}
'''

from __future__ import print_function

import json
import boto3
import responses
import os
from botocore.exceptions import ClientError

account_mode = os.getenv('ACCOUNT_MODE', '')
cross_account_role_name = os.getenv('CROSS_ACCOUNT_ROLE_NAME', '')
all_session_credentials = {}


def lambda_handler(event, context):
    # get SNS message
    raw_message = event['Records'][0]['Sns']['Message']

    # notification message from CWP is json of the relevant alert or misconfiguration (hardening)
    source_message = json.loads(raw_message)
    process_message(source_message)


def process_message(source_message):
    # Get the session info
    try:  # get the accountID
        sts = boto3.client('sts')
        lambda_account_id = sts.get_caller_identity()['Account']

    except ClientError as e:
        print(f'{__file__} Unexpected STS error - {e}')

    print(f'\nLambda Execution Account: {lambda_account_id}')
    for failed_resource in source_message['failedResources']:

        failed_resource_account_id = failed_resource['accountId']
        print(f'\nFailed Resource Account: {failed_resource_account_id}')

        # Account mode will be set in the lambda variables. Default to single mode
        if lambda_account_id != failed_resource_account_id:  # The remediation needs to be done outside of this account
            if account_mode == 'multi':  # multi or single account mode?
                # If it's not the same account, try to assume role to the new one
                print("\nThe AWS account of this Lambda execution role does not match the account of the target failed resource. \nMulti-account mode detected and activated.")
                role_arn = ''.join(['arn:aws:iam::', failed_resource_account_id, ':role/'])
                # This allows users to set their own role name if they have a different naming convention
                role_arn = ''.join([role_arn, cross_account_role_name]) if cross_account_role_name else ''.join([role_arn, 'RadwareCWPAutomatedResponse'])

                global all_session_credentials
                # create an STS client object that represents a live connection to the STS service
                sts_client = boto3.client('sts')

                # Call the assume_role method of the STSConnection object and pass the role ARN and a role session name.
                try:
                    assumed_role_object = sts_client.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName='CWPAutomatedResponse'
                    )
                    # From the response that contains the assumed role, get the temporary credentials that can be used to make subsequent API calls
                    all_session_credentials[failed_resource_account_id] = assumed_role_object['Credentials']
                    credentials_for_event = all_session_credentials[failed_resource_account_id]

                except ClientError as e:
                    error = e.response['Error']['Code']
                    print(f'{__file__} - Error - {e}')
                    if error == 'AccessDenied':
                        print(
                            'Tried and failed to assume a role in the target account. Please verify that the cross account role is createad.')
                    else:
                        print(f'Unexpected Error: {e}')

                boto_session = boto3.Session(
                    region_name=failed_resource['region'],
                    aws_access_key_id=credentials_for_event['AccessKeyId'],
                    aws_secret_access_key=credentials_for_event['SecretAccessKey'],
                    aws_session_token=credentials_for_event['SessionToken']
                )

                trigger_response(boto_session, source_message)

            else:
                # In single account mode, we don't want to try to execute a Response outside of this account therefore
                # the lambda will exit with error
                print(
                    f'This finding was found in account id {failed_resource_account_id}. The Lambda function is running in account id: {lambda_account_id}. Remediations need to be ran from the account there is the issue in.')
        else:
            trigger_response(boto3, source_message)


def trigger_response(boto_session, source_message):
    if source_message['objectType'] == 'AlertEntity':
        alert = source_message
        print("alert=" + str(alert))
        responses.handle_alert(boto_session, alert)
    elif source_message['objectType'] == 'WarningEntity':
        hardening = source_message
        print("hardening=" + str(hardening))
        responses.handle_hardening(boto_session, hardening)








