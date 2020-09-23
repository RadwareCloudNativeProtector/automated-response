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


required permissions:
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
    "logs:PutLogEvents"
'''

from __future__ import print_function

import json
import boto3
import responses

print('Loading function')


def lambda_handler(event, context):
    # get SNS message
    message = event['Records'][0]['Sns']['Message']

    # notification message from CWP is json of the relevant alert or misconfiguration (hardening)
    message_object = json.loads(message)
    print('XXXXXXXX')
    print(message_object)

    if message_object['objectType'] == 'AlertEntity':
        alert = message_object
        print("alert=" + str(alert))
        handle_alert(alert)
    elif message_object['objectType'] == 'WarningEntity':
        hardening = message_object
        print("hardening=" + str(hardening))
        handle_hardening(hardening)


def handle_alert(alert):
    # handle alert
    # create aws client for ec2 service
    ec2_client = boto3.client('ec2')
    # create aws client for iam service
    iam_client = boto3.client('iam')
    # create aws client for rds service
    rds_client = boto3.client('rds')
    # create aws client for cloudtrail service
    cloudtrail_client = boto3.client('cloudtrail')
    # create aws client for s3 service
    s3_client = boto3.client('s3')

    # involved identities are users and roles which were somehow part of the alert -
    # extract only users (roles are also in involvedIdentities)
    users = [involvedIdentity for involvedIdentity in alert['involvedIdentities'] if 'user' in involvedIdentity['id']]

    '''you can delete user login profile to block console login
        or/and deactivate access key to block cli usage
        or set permission boundary to make all methods unavailable for the user'''
    user_names = [user['name'] for user in users]
    responses.delete_users_login_profile(iam_client, user_names)
    responses.deactivate_users_access_keys(iam_client, user_names)
    responses.set_deny_all_permission_boundary(iam_client, users)

    # involved resources are machines which were somehow part of the alert and check that we have the instanceId
    machines = [involvedResource for involvedResource in alert['involvedResource'] if 'id' in involvedResource]

    '''you can disassociate role from machine
        or/and quarantine instance by security group
        or/and simply stop the machine'''
    responses.disassociate_role_from_machines(ec2_client, iam_client, machines)
    responses.quarantine_instances_by_security_group(ec2_client, machines)
    responses.stop_instances(ec2_client, machines)

    # find all rds involved - put in set to avoid duplications
    rds_dbs = {activity['affectedResources']['rds'] for activity in alert['activities'] if 'rds' in activity['affectedResources']}
    # quarantine rds by security group (DB security group and VPC security group) and reboot to stop
    # current open connections
    responses.quarantine_rds_by_security_group(rds_client, ec2_client, rds_dbs)

    # get tail ARN of the activities with name like "cloudtrailStopLogs", if so - start CloudTrail logging
    cloudtrial_arns = [activity['affectedResources']['trailName'] for activity in alert['activities'] if activity['name'] == 'cloudtrailStopLogs' and 'trailName' in activity['affectedResources']]
    responses.start_cloudtrail_logging(cloudtrail_client, cloudtrial_arns)

    # get bucket names of the activities with name like "publicS3Bucket",
    # if bucket made publicly accessible - block its public access
    buckets = [activity['affectedResources']['bucketName'] for activity in alert['activities'] if activity['name'] == 'publicS3Bucket' and 'bucketName' in activity['affectedResources']]
    responses.block_public_access(s3_client, buckets)


def handle_hardening(hardening):
    # handle hardening
    # create aws client for iam service
    iam_client = boto3.client('iam')
    # create aws client for ec2 service
    ec2_client = boto3.client('ec2')
    # create aws client for rds service
    rds_client = boto3.client('rds')

    if hardening['hardeningType'] == 'Misconfiguration':
        responses.handle_misconfiguration(iam_client, hardening)
    elif hardening['hardeningType'] == 'ExposedMachines':
        responses.handle_exposed_machines(ec2_client, hardening)
    elif hardening['hardeningType'] == 'ExposedDatabase':
        responses.handle_exposed_database(ec2_client, rds_client, hardening)
    elif hardening['hardeningType'] == 'PublicS3Bucket':
        responses.handle_public_bucket(hardening)



