Buckets

A good tool to review your configuration in several clouds is: https://github.com/nccgroup/ScoutSuite​

​AWS S3 hacking tricks​

More info:

    ​https://www.notsosecure.com/cloud-services-enumeration-aws-azure-and-gcp/​

    ​https://www.notsosecure.com/exploiting-ssrf-in-aws-elastic-beanstalk/​

    ​https://www.notsosecure.com/identifying-exploiting-leaked-azure-storage-keys/

AWS-S3
Amazon S3 Buckets

A bucket is typically considered “public” if any user can list the contents of the bucket, and “private” if the bucket's contents can only be listed or written by certain S3 users. This is important to understand and emphasize. A public bucket will list all of its files and directories to an any user that asks.

It should be emphasized that a public bucket is not a risk created by Amazon but rather a misconfiguration caused by the owner of the bucket. And although a file might be listed in a bucket it does not necessarily mean that it can be downloaded. Buckets and objects have their own access control lists (ACLs).  Amazon provides information on managing access controls for buckets here. Furthermore, Amazon helps their users by publishing a best practices document on public access considerations around S3 buckets. The default configuration of an S3 bucket is private.

Learn about AWS-S3 misconfiguration here:  http://flaws.cloud and http://flaws2.cloud/ (Most of the information here has been take from those resources)
Regions

    US Standard = http://s3.amazonaws.com

    Ireland = http://s3-eu-west-1.amazonaws.com

    Northern California = http://s3-us-west-1.amazonaws.com

    Singapore = http://s3-ap-southeast-1.amazonaws.com

    Tokyo = http://s3-ap-northeast-1.amazonaws.com

AWS Configuration

Prerequisites, at least you need awscli

sudo apt install awscli

You can get your credential here https://console.aws.amazon.com/iam/home?#/security_credential but you need an aws account, free tier account : https://aws.amazon.com/s/dm/optimization/server-side-test/free-tier/free_np/​

aws configure --profile <PROFILE_NAME>
AWSAccessKeyId=[ENTER HERE YOUR KEY]
AWSSecretKey=[ENTER HERE YOUR KEY]

Alternatively you can use environment variables instead of creating a profile.

export AWS_ACCESS_KEY_ID=ASIAZ[...]PODP56
export AWS_SECRET_ACCESS_KEY=fPk/Gya[...]4/j5bSuhDQ
export AWS_SESSION_TOKEN=FQoGZXIvYXdzE[...]8aOK4QU=

Finding AWS Buckets used by the target

Different methods to find when a webpage is using AWS to storage some resources:

    Using wappalyzer browser plugin

    Using BURP (spidering the web) or by manually navigating through the page all resources loaded will be save in the History.

    Check for resources in domains like:

    http://s3.amazonaws.com/[bucket_name]/
    http://[bucket_name].s3.amazonaws.com/

Notice that a domain could be hiding some of this URLs for example resources.domain.com --> bucket.s3.amazonaws.com

You can get the region of a bucket with a dig and nslookup:

$ dig flaws.cloud
;; ANSWER SECTION:
flaws.cloud.    5    IN    A    52.218.192.11
​
$ nslookup 52.218.192.11
Non-authoritative answer:
11.192.218.52.in-addr.arpa name = s3-website-us-west-2.amazonaws.com.

Check that the resolved domain have the word "website".
You can access the static website going to: flaws.cloud.s3-website-us-west-2.amazonaws.com 
or you can access the bucket visiting:  flaws.cloud.s3-us-west-2.amazonaws.com

If you tries to access a bucket but in the domain name you specifies another region (for example the bucket is in bucket.s3.amazonaws.com but you try to access bucket.s3-website-us-west-2.amazonaws.com you will be redirected to the correct location.
Enumerating the bucket

To test the openness of the bucket a user can just enter the URL in their web browser. A private bucket will respond with "Access Denied". A public bucket will list the first 1,000 objects that have been stored.

Open to everyone:

Private:

You can also check this with the aws tool: 

#Use --no-sign-request for check Everyones permissions
#Use --profile <PROFILE_NAME> to indicate the AWS profile(keys) that youwant to use: Check for "Any Authenticated AWS User" permissions
#--recursive if you want list recursivelyls 
#Opcionally you can select the region if you now it
aws s3 ls  s3://flaws.cloud/ [--no-sign-request] [--profile <PROFILE_NAME>] [ --recursive] [--region us-west-2]

If the bucket doesn't have a domain name, when trying to enumerate it, only put the bucket name and not the hole AWSs3 domain. Example: s3://<BUCKETNAME>
Enumerating a AWS User

If you find some private AWS keys, you can create a profile using those:

aws configure --profile flawscloud

Notice that if you find a users credentials in the meta-data folder, you will need to add the aws_session_token to the profile.
Get buckets

And the check to which buckets this profile is related to (may or may not have access to them):

aws s3 ls --profile flawscloud

User Information

Check the UserId, Account number and UserName doing:

aws --profile flawscloud sts get-caller-identity

aws iam get-user --profile level6

Get User Policies

aws iam list-attached-user-policies --profile <Profile> --user-name <UserName>

To get information about a policy you first need the DefaultVersionId:

aws iam get-policy --profile <PROFILE> --policy-arn <POLICY_ARN> #Example: arn:aws:iam::975426262029:policy/list_apigateways

Now, you can see the policy:

aws iam get-policy-version --profile level6 --policy-arn arn:aws:iam::975426262029:policy/list_apigateways --version-id v4

This means that you can access GET arn:aws:apigateway:us-west-2::/restapis/*

Now it's time to find out possible lambda functions to execute:

aws --region us-west-2 --profile level6 lambda list-functions

A lambda function called "Level6" is available. Lets find out how to call it:

aws --region us-west-2 --profile level6 lambda get-policy --function-name Level6

Now, that you know the name and the ID you can get the Name:

aws --profile level6 --region us-west-2 apigateway get-stages --rest-api-id "s33ppypa75"

And finally call the function accessing (notice that the ID, Name and functoin-name appears in the URL): https://s33ppypa75.execute-api.us-west-2.amazonaws.com/Prod/level6​
User privileges enumeration and privilege escalation

Try the tool: pacu​
Find and Download Elastic Container Registry

## Find
aws ecr list-images --repository-name <ECR_name> --registry-id <UserID> --region <region> --profile <profile_name>
## Download
aws ecr get-login
docker pull <UserID>.dkr.ecr.us-east-1.amazonaws.com/<ECRName>:latest
docker inspect sha256:079aee8a89950717cdccd15b8f17c80e9bc4421a855fcdc120e1c534e4c102e0

Get Snapshots

Notice that AWS allows you to make snapshots of EC2's and databases (RDS). The main purpose for that is to make backups, but people sometimes use snapshots to get access back to their own EC2's when they forget the passwords.

Look for snapshots this user has access to (note the SnapshotId):

#This timeyou need to specify the region
aws  ec2 describe-snapshots --profile flawscloud --owner-id 975426262029 --region us-west-2

If you run that command without specifying the --owner-id you can see how many publicly available EC2 snapshots are.
Mounting an EC2 snapshot

Create a copy of the backup:

aws ec2 create-volume --profile YOUR_ACCOUNT --availability-zone us-west-2a --region us-west-2  --snapshot-id  snap-0b49342abd1bdcb89

Mount it in a EC2 VM under your control (it has to be in the same region as the copy of the backup):

step 1: Head over to EC2 –> Volumes and create a new volume of your preferred size and type.

Step 2: Select the created volume, right click and select the “attach volume” option.

Step 3: Select the instance from the instance text box as shown below.​attach ebs volume​​

Step 4: Now, login to your ec2 instance and list the available disks using the following command.

lsblk

The above command will list the disk you attached to your instance.

Step5:
SSRF attacks through AWS

If you want to read about how can you exploit meta-data in AWS you should read this page​

​
Tools to scan the configuration of buckets or to discover buckets
sa7mon/S3Scanner
Scan for open AWS S3 buckets and dump the contents - sa7mon/S3Scanner
github.com
clario-tech/s3-inspector
Tool to check AWS S3 bucket permissions. Contribute to clario-tech/s3-inspector development by creating an account on GitHub.
github.com
jordanpotti/AWSBucketDump
Security Tool to Look For Interesting Files in S3 Buckets - jordanpotti/AWSBucketDump
github.com
https://github.com/hehnope/slurp
github.com
fellchase/flumberboozle
Suite of programs meant to aid in bug hunting and security assessments  - fellchase/flumberboozle
github.com
smaranchand/bucky
Bucky (An automatic S3 bucket discovery tool). Contribute to smaranchand/bucky development by creating an account on GitHub.
github.com

​
List of Open Buckets
Public Buckets by GrayhatWarfare
buckets.grayhatwarfare.com

​
