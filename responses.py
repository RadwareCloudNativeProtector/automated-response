import datetime


def handle_misconfiguration(iam_client, hardening):
    # handle misconfiguration
    # extract misconfiguration rule id
    rule_id = hardening['ruleId']

    if rule_id == 'RDWR.AWS.IAM.UserMFAEnabled':
        # make sure resource type is IamUser
        assert hardening['resourceType'] == 'User'

        # this will extract all usernames of users which 'failed' some misconfiguration rule on IamUser
        users = [user['name'] for user in hardening['failedResources']]

        # you can delete user login profile to block console login
        delete_users_login_profile(iam_client, [user for user in users if check_user_created_at_least_day_ago(iam_client, user)])

    elif rule_id == 'RDWR.AWS.IAM.UnusedCredentials1ShouldBeDisabled':
        # make sure resource type is IamUser
        assert hardening['resourceType'] == 'User'

        # this will extract all usernames of users which 'failed' some misconfiguration rule on IamUser
        users =[user['name'] for user in hardening['failedResources']]

        # you can deactivate access key to block cli usage
        deactivate_users_access_keys(iam_client, users)


def handle_public_bucket(hardening):
    # handle public buckets
    return


def handle_exposed_machines(ec2_client, hardening):
    # handle exposed machines
    """
    # if SSh(port 22), RDP(port 3389) or all ports are open, remove the exposed port from security group inbound ip permissions
    if '22' in hardening['openPorts'] or '3389' in hardening['openPorts'] or '0-65535' in hardening['openPorts']:
        remove_exposed_port_from_inbound(ec2_client, hardening['securityGroup'], [22, 3389])
    """
    stop_instances(ec2_client, hardening['failedResources'])


def handle_exposed_database(ec2_client, rds_client, hardening):
    # handle exposed databases
    # check if type of security group is VPC(EC2) or DB
    if hardening['securityGroup']['type'] == 'EC2':
        remove_exposed_port_from_inbound(ec2_client, hardening['securityGroup'], hardening['openPorts'])
    elif hardening['securityGroup']['type'] == 'DB':
        remove_cidrip_from_db_sg(rds_client, hardening['securityGroup'])


def remove_cidrip_from_db_sg(rds_client, security_group):
    # remove exposed inbound CIDR/IP from DB security group
    try:
        # remove open inbound CIDR/IP from DB security group
        rds_client.revoke_db_security_group_ingress(DBSecurityGroupName=security_group['name'],CIDRIP='0.0.0.0/0')
        print("modified DB security group: " + str(security_group))
    except Exception as e:
        print("could not modify DB security group " + str(security_group) + ". message: " + str(e))


def remove_exposed_port_from_inbound(ec2_client, security_group, ports):
    # remove exposed inbound ip permissions from ec2 (vpc) security group
    try:
        # describe security group in order to get its inbound ip permissions
        groups = ec2_client.describe_security_groups(GroupIds=[security_group['id']])
        for group in groups['SecurityGroups']:
            try:
                # remove all ip permissions which are open (all ports, SSH(22), RDP(3389))
                ip_permissions = [ip_permission for ip_permission in group['IpPermissions']
                                if (any(ip_range['CidrIp'] == '0.0.0.0/0' for ip_range in ip_permission['IpRanges']) or any(ipv6_range['CidrIpv6'] == '::/0' for ipv6_range in ip_permission['Ipv6Ranges']))
                                and ((ip_permission['IpProtocol'] == '-1' or (ip_permission['FromPort'] == 0 and ip_permission['ToPort'] == 65535))
                                or any((ip_permission['FromPort'] <= port <= ip_permission['ToPort']) for port in ports))]

                # remove open inbound ip permissions from security group
                ec2_client.revoke_security_group_ingress(GroupId=group['GroupId'],IpPermissions=ip_permissions)
                print("modified security group: " + str(group))
            except Exception as e:
                print("could not modify security group " + str(group) + ". message: " + str(e))
    except Exception as e:
            print("could not describe security group " + str(security_group) + ". message: " + str(e))


def block_public_access(s3_client, buckets):
    # block public access of buckets
    for bucket in buckets:
        try:
            s3_client.put_public_access_block(Bucket=bucket,PublicAccessBlockConfiguration={'BlockPublicPolicy': True})
            print("blocked public access for " + str(bucket))
        except Exception as e:
            print("could not block public access for " + str(bucket) + ". message: " + str(e))


def start_cloudtrail_logging(cloudtrail_client, cloudtrial_arns):
    # start cloudtrail logging
    for cloudtrial_arn in cloudtrial_arns:
        try:
            cloudtrail_client.start_logging(Name=cloudtrial_arn)
            print("started cloudtrail logging for " + str(cloudtrial_arn))
        except Exception as e:
            print("could not start cloudtrail logging " + str(cloudtrial_arn) + ". message: " + str(e))


def stop_instances(ec2_client, machines):
    # simply stop instance
    for machine in machines:
        try:
            instance_id = machine['id']

            # in order to close current connection we must stop/reboot the instance by instance id
            ec2_client.stop_instances(InstanceIds=[instance_id],Force=True)
            print("stopped instance " + str(instance_id))

        except Exception as e:
            print("could not stop instance " + str(machine) + ". message: " + str(e))


def get_empty_security_group(ec2_client, vpc_id):
    # find or create if not exists new empty security group
    group_name = 'RadwareCwpEmptySecurityGroup_' + vpc_id
    try:
        security_group_list = ec2_client.describe_security_groups(GroupNames=[group_name])
        security_group = security_group_list['SecurityGroups'][0]
        print("found security group: " + str(security_group))
    except:
        group_id_map = ec2_client.create_security_group(Description='security group with no inbound/outbound permission for CWP', GroupName=group_name, VpcId=vpc_id)
        # describe again
        security_group_list = ec2_client.describe_security_groups(GroupIds=[group_id_map['GroupId']])
        security_group = security_group_list['SecurityGroups'][0]
        print("created security group: " + str(security_group))

    # make sure that there are no inbound and outbound permissions
    if len(security_group['IpPermissionsEgress']) > 0:
        ec2_client.revoke_security_group_egress(GroupId=security_group['GroupId'],IpPermissions=security_group['IpPermissionsEgress'])
    if len(security_group['IpPermissions']) > 0:
        ec2_client.revoke_security_group_ingress(GroupId=security_group['GroupId'],IpPermissions=security_group['IpPermissions'])

    return security_group['GroupId']


def quarantine_rds_by_security_group(rds_client, ec2_client, rds_dbs):
    # quarantine rds by associating it to security group which has no inbound/outbound permissions
    for rds in rds_dbs:
        modified = False
        # modify rds instance security group and vpc security group to security group that has no inbound/outbound permission by db instance  and by security group id
        try:
            # describe rds in order to get its vpc
            rds_list = rds_client.describe_db_instances(DBInstanceIdentifier=rds)
            rds_details = rds_list['DBInstances'][0]
            security_group_id = get_empty_security_group(ec2_client, rds_details['DBSubnetGroup']['VpcId'])

            rds_client.modify_db_instance(DBInstanceIdentifier=rds,DBSecurityGroups=[security_group_id],ApplyImmediately=True)
            print("modified rds instance " + str(rds) + " security group to " + str(security_group_id))
            modified = True
        except Exception as e:
            print("could not modify rds instance security group " + str(rds) + ". message: " + str(e))

        try:
            rds_client.modify_db_instance(DBInstanceIdentifier=rds,VpcSecurityGroupIds=[security_group_id])
            print("modified rds instance " + str(rds) + " vpc security group to " + str(security_group_id))
            modified = True
        except Exception as e:
            print("could not modify rds instance vpc security group " + str(rds) + ". message: " + str(e))

        if modified:
            try:
                # in order to close current connection we must also reboot the rds instance by db instance identifier
                rds_client.reboot_db_instance(DBInstanceIdentifier=rds)
                print("rebooted rds instance " + str(rds) + " to interrupt current connections")
            except Exception as e:
                print("could not reboot rds " + str(rds) + ". message: " + str(e))


def quarantine_instances_by_security_group(ec2_client, machines):
    # quarantine instance by associating it to security group which has no inbound/outbound permissions
    for machine in machines:
        try:
            instance_id = machine['id']
            vpc_id = machine['vpcId']
            security_group_id = get_empty_security_group(ec2_client, vpc_id)
            # modify instance security group to security group that has no inbound/outbound permission by instance id and by security group id
            ec2_client.modify_instance_attribute(InstanceId=instance_id,Groups=[security_group_id])
            print("modify instance " + str(instance_id) + " security group to " + str(security_group_id))

            try:
                # in order to close current connection we must also reboot the instance by instance id
                ec2_client.reboot_instances(InstanceIds=[instance_id])
                print("rebooted instance " + str(instance_id) + " to interrupt current connections")

            except Exception as e:
                print("could not reboot machine " + str(machine) + ". message: " + str(e))

        except Exception as e:
            print("could not modify security group for machine " + str(machine) + ". message: " + str(e))


def disassociate_role_from_machines(ec2_client, iam_client, machines):
    # describe instance association profiles and disassociate the from instance
    # inline policy to revoke all role sessions
    role_revoke_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":[\"*\"],\"Resource\":[\"*\"],\"Condition\":{\"DateLessThan\":{\"aws:TokenIssueTime\":\"%s\"}}}]}"

    for machine in machines:
        try:
            instance_id = machine['id']
            # get all instance profile associations by instance id
            response = ec2_client.describe_iam_instance_profile_associations(Filters=[{'Name': 'instance-id','Values': [instance_id]},{'Name': 'state','Values': ['associating','associated']}])
            iam_instance_profile_associations = response['IamInstanceProfileAssociations']

            # iterate through all profiles and disassociate them from instance
            for iam_instance_profile_association in iam_instance_profile_associations:
                try:
                    # disassociate instance profile by association id
                    ec2_client.disassociate_iam_instance_profile(AssociationId=iam_instance_profile_association['AssociationId'])
                    print("disassociated iam instance profile " + str(iam_instance_profile_association))

                    try:
                        # extract role name from arn of profile association
                        role_name = iam_instance_profile_association['IamInstanceProfile']['Arn'].split('/')[-1]

                        #  Current Time
                        time = datetime.datetime.utcnow().isoformat()

                        # the attacker might have assumed the role and can use it up to 12 hours unless we revoke the active sessions
                        iam_client.put_role_policy(RoleName=role_name,PolicyName='AWSRevokeOlderSessions',PolicyDocument=role_revoke_policy % time)
                        print("revoked role: " + str(role_name))

                    except Exception as e:
                        print("could not revoke role " + str(role_name) + ". message: " + str(e))

                except Exception as e:
                    print("could not Disassociate iam instance profile for " + str(iam_instance_profile_association) + ". message: " + str(e))

        except Exception as e:
            print("could not Describe and Disassociate Role From Machine for " + str(machine) + ". message: " + str(e))


def get_deny_all_policy(iam_client, account_id):
    # get deny all policy if exists or create it if it doesn't
    deny_policy_name = 'CwpDenyAllPolicy'
    deny_policy_arn = 'arn:aws:iam::' + account_id + ':policy/' + deny_policy_name
    deny_policy_permissions = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":[\"*\"],\"Resource\":[\"*\"]}]}"

    try:
        # get policy by policy arn
        deny_policy = iam_client.get_policy(PolicyArn=deny_policy_arn)
        print("found policy " + deny_policy_name)
    except Exception as e:
        # check if no policy with the above arn was found
        if e.response['Error']['Code'] == 'NoSuchEntity':
            # create policy with the above details
            deny_policy = iam_client.create_policy(PolicyName=deny_policy_name, PolicyDocument=deny_policy_permissions, Description='Deny All Policy for CWP')
            print("created policy " + deny_policy_name)
        else:
            print("error in get_deny_all_policy: " + str(e))
            return None

    return deny_policy['Policy']['Arn']


def set_deny_all_permission_boundary(iam_client, involved_users):
    # set deny all permission boundary for all involved users
    if len(involved_users) > 0:
        # get the account id
        account_id = involved_users[0]['id'].split(':')[4]
        # get or create deny policy - return arn
        deny_policy_arn = get_deny_all_policy(iam_client, account_id)

        for involved_user in involved_users:
            try:
                user_name = involved_user['name']
                iam_client.put_user_permissions_boundary(UserName=user_name, PermissionsBoundary=deny_policy_arn)
                print("DenyAll Permission Boundary was set to " + str(involved_user))
            except Exception as e:
                print("could not set DenyAll Permission Boundary to " + str(involved_user) + ". message: " + str(e))
    else:
        print("involved users list is empty")


def deactivate_users_access_keys(iam_client, user_names):
    # describe users access keys and deactivate them
    for user_name in user_names:
        try:
            # get all access keys of the user
            res = iam_client.list_access_keys(UserName=user_name)
            # extract keys from metadata
            keys = [key['AccessKeyId'] for key in res['AccessKeyMetadata']]

            # deactivate all user's access keys
            for key in keys:
                try:
                    iam_client.update_access_key(AccessKeyId=key, UserName=user_name, Status='Inactive')
                    print("deactivated " + str(user_name) + " access key " + str(key))
                except Exception as e:
                    print("could not deactivate " + str(user_name) + " access key " + str(key) + ". message: " + str(e))
        except Exception as e:
            print("could not deactivate " + str(user_name) + " access keys. message: " + str(e))


def delete_users_login_profile(iam_client, user_names):
    # delete users login profile and block console login
    for user_name in user_names:
        try:
            iam_client.delete_login_profile(UserName=user_name)
            print("deleted/disabled " + str(user_name) + " login profile")
        except Exception as e:
            print("could not delete/disable " + str(user_name) + " login profile. message: " + str(e))


def check_user_created_at_least_day_ago(iam_client, user_name):
    # check that the user was created at least a full day ago
    try:
        describe_user = iam_client.get_user(UserName=user_name)
        # get yesterday's date
        yesterday = datetime.datetime.now() - datetime.timedelta(days=1)
        # compare user create date (without time zone) with yesterday date
        if describe_user['User']['CreateDate'].replace(tzinfo=None) <= yesterday:
            print("user was created before the last 24H: " + str(describe_user))
            return True
        else:
            print("user was created in the last 24H: " + str(describe_user))
            return False
    except Exception as e:
        print("could not describe " + str(user_name) + ", continuing. message: " + str(e))
        return False