# Radware CWP Automated Response

This open source AWS tool consumes the published security findings detected in Radware CWP to then trigger a response in the AWS account of the resource. This project covers several example use cases, such as: quarantine a user involved in an attack, quarantine a compromised machine, disable AWS console access for users without Multi-Factor Authentication, deactivate unused user access keys and many more.

The CFT deployment process will create an SNS Topic, an IAM Role, CloudWatch Log Group (default 731 days retention), and a Lambda Function. Messages published to the created SNS Topic trigger the Lambda Function on-demand.

## Setup

### CFT Parameters
This CFT stack has 2 parameters:

- **DeploymentMode** -  Deployment Mode - can be single-account or multi-account (STS assume-role)
- **CrossAccountAccessRole** - Cross-account access role name for multi-account response mode. Ignore if using single-account response mode.

### [Option 1] One-click CFT Deployment:
[<img src="docs/pictures/cloudformation-launch-stack.png">](https://console.aws.amazon.com/cloudformation/home?#/stacks/new?stackName=RadwareCWP-Automated-Response&templateURL=https://radware-cwp-devops-us-east-1.s3.amazonaws.com/radware_cwp_automated_response/radware_cwp_automated_reponse_cftemplate.yaml)
> Note: One-click CFT deployment currently works for regions: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-central-1. The AWS region you are actively logged into will be the region of deployment.
1. Fill in the parameter fields. 
1. Click **Next** twice.
1. Under **Capabilities and transforms**, click to check the **3** pending acknowledgements: "_I acknowledge..._".
1. Click **Create stack**.
1. After the process finished view the **Outputs** tab. The **InputTopicARN** value will be needed for the next step in the CWP console.

### [Option 2] Manual CFT Deployment:
1. Download the contents of this repo.
1. Build your own Lambda deployment file (see [Appendix A](#appendix-A))
1. Upload the deployment file to an S3 bucket 
1. Modify `radware_cwp_automated_response.yaml` lines `47` and `53` and enter values for `bucket` and `key` (zip file), respectively. Remove lines `48-51`.
1. Login to the AWS console, select a region, and navigate to CloudFormation. 
1. Click **Create stack**
1. Under **Specify template**, click **Upload a template file**
1. Click the **Choose file** button and upload the modified CFT.
1. Click **Next** twice.
1. Under **Capabilities and transforms**, click to check the **3** pending acknowledgements: "_I acknowledge..._". (or use "--capabilities CAPABILITY_IAM" if using the AWS CLI.)
1. Click **Create stack**.
1. After the process finished view the **Outputs** tab. The **InputTopicARN** value will be needed for the next step in the Radware CWP console.

## Deploy for Multi-account mode

For multi-account mode you will setup one account using the deployment CFT above as the central account for CWP automated responses.
For each additional account that the central account will manage you will set up a cross-account access role and policy.

On the AWS CFT console, for your account, perform these steps:

1.  Set the ACCOUNT\_MODE environment variable to *multi*.
2.  Edit the *trust\_policy.json* file (in the
    *cross\_account\_role\_scripts* folder),to add the account id of the
    additional account. Then, run the following commands:

<!-- end list -->

    cd cross_account_role_scripts
    ./create_role.sh <aws profile>

This script will create the IAM role and policy for the additional account.


## Post-Deployment Steps

### Radware CWP Setup:
1. Log into **Radware CWP** and then click **Settings** > **Manage Cloud Accounts** from the menu at the top. 
1. Find the AWS cloud account you want to get alerts from in the list, click **Activate** under the **Automated Response** column.
1. In the **Activate Automated Response** dialogue box, under step 2, paste the **InputTopicARN** value from the CFT deployment process. 
1. Click **Activate**.
All done!

### Testing:
##### Option 1: Synthetic Test
1. Find the sample CWP JSON files in the `samples` directory from this repo for *WarningEntity* and *Alert* payloads.
1. From the CFT stack deployment in the AWS Console, open the SNS topic found in the **Resources** tab, shown as **InputTopic**.
1. At the top-right, click the **Publish message** button and copy and paste the contents of one of the JSON files into the **Message body** field. (You may need the ``score`` value in the payload to include a value in your `CwpScoreFilter` parameter)
1. Scroll down and click the **Publish messsage** button. 
1. Validate the results in S3.

##### Option 2 - CWP Native Test
It is recommended to perform the synthetic test first before attempting a CWP native test.
1. Temporarily set the `CwpScoreFilter` parameter to `4,5,6,7,8,9,10`
1. Login to an AWS account that is already protected by Radware CWP with [automated response](#radware-cwp-setup).
1. Create a test S3 bucket and set the bucket policy to allow public acess. You should see Public warnings in the AWS console. This will trigger CWP and push a *WarningEntity* payload.
1. Validate the Lambda function logs and the results in S3.
1. Reset the `CwpScoreFilter` parameter to the desired value (e.g. `7,8,9,10`)
1. Cleanup the S3 bucket created for this test.



## License
This project is licensed under the MIT License
