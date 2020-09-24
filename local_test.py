#!/usr/bin/python

import lambda_function

"""
    This is a local test file to test and debug your bots execution in your local environment
    The way to use it is by filling the message variable with the relevant Dome9 notification record that should trigger your bot 
    You can use some notification samples from sample_compliance_notification folder 
    Or sample it from the output sns that Dome9 send it to 
"""

message = r'''
    {
        "accountIds": [
            "547540466142"
        ],
        "accountName": "Radware Test",
        "cloudPlatform": null,
        "objectType": "WarningEntity",
        "objectPortalURL": "https://portal.cwp.radwarecloud.com/#/data-center/hardening/338392969745",
        "id": "338392789745",
        "title": "Multiple ports of 1 machine exposed by security group DetectionTierSG_DavidJ ",
        "score": "3",
        "createdDate": "2020-09-21T18:31:20",
        "vendor": "Radware",
        "apiVersion": "1.00",
        "hardeningType": "ExposedMachines",
        "status": "NEW",
        "category": "exposedMachines",
        "resourceType": "Instance",
        "lastDetectionDate": "2020-09-21T18:31:20",
        "description": "The current configuration  of security group DetectionTierSG_DavidJ allows anyone on the internet to access multiple ports of 1 machine. Machines using this security group might be  exploited by threat actors to gain access to your workloads and data.",
        "recommendation": "Modify the rules of  of security group DetectionTierSG_DavidJ so that it doesn't allow unrestricted ingress access to multiple ports.",
        "subject": "Publicly exposed ports on 1 machine - detected in account Radware SSA (ID: 334049999223)",
        "failedResources": [
            {
                "accountId": "547540466142",
                "accountVendor": "AWS",
                "name": "Detection1-DO_NOT_DELETE",
                "id": "i-0939ebc7c8834bd5b",
                "vpcId": "vpc-0da800c9e3d3b69fb",
                "tags": [
                    {
                        "key": "Name",
                        "value": "Detection1-DO_NOT_DELETE"
                    },
                    {
                        "key": "Owner",
                        "value": "davidj"
                    },
                    {
                        "key": "shutdown",
                        "value": "18527"
                    },
                    {
                        "key": "start",
                        "value": "18404"
                    }
                ],
                "createdDate": "2020-09-22T18:37:03",
                "passed": false,
                "region": "us-east-1",
                "instanceType": "t3a.medium",
                "ipAddresses": [
                    "66.22.109.7",
                    "172.16.254.119"
                ],
                "ami": "ami-07ebfd5b3428b6f4d",
                "status": "stopped",
                "publicIp": "66.22.109.7"
            }
        ]
    }
'''



sns_event = {
    'Records': [{
        'EventSource': 'aws:sns',
        'EventVersion': '1.0',
        'EventSubscriptionArn': 'arn:aws:sns:us-east-1:123007184456:CwpResponse:0c77780c-177f-4771-9770-b3c777ac7836',
        'Sns': {
            'Type': 'Notification',
            'MessageId': 'd57748d6-f779-577f-b773-1a1e4777de5c',
            'TopicArn': 'arn:aws:sns:us-east-1:123007184456:CwpResponse',
            'Subject': 'CWP Event',
            'Message': message,
            'Timestamp': '2018-01-04T23:10:30.652Z',
            'SignatureVersion': '1',
            'Signature': 'fKnhKjUiOdDIKslbL54A2ZjIiGc/NPw==',
            'SigningCertUrl': 'https://sns.us-west-2.amazonaws.com/SimpleNotificationService-777026a4050d206028897774da859041.pem',
            'UnsubscribeUrl': 'https://sns.us-west-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-1:123007184456:CwpResponse:0cf0e80c-1fef-4421-9cc0-b3c102ac7836',
            'MessageAttributes': {}
        }
    }]
}


context = ""


lambda_function.lambda_handler(sns_event, context)