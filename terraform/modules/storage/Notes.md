Without the Condition in  the storage policies : (example of the CloudTrail policy )
+ CloudTrail creates the logs -> And has comlete ownerships over the logs -> So we can't delete /modify the logs ( which is crucial in our case where we delete the old logs for ressources managment and wost effectiveness too )
+ With condition we maintian control over the logs -> We can delete / modify , edit lifecycle , encrypt ..

 The S3 policy Flow : 
 1. we enable CloudTrail -> S3 bucket 
 2. CloudTrail checks if it can access the S3 bucket : checks the bucketACL 
 3. ALLOWED 
 4. CloudTrail can acces and write logs in the bucket 
 5. Condition: AS explained above 
 6. 

 # ❌ RONG - Too permissive
resources = ["${bucket.arn}/*"]  # Allows writing ANYWHERE 

--> That's why we use this approach  
#  CORRECT - Specific folders only
resources = ["${bucket.arn}/cloudtrail/*"]
resources = ["${bucket.arn}/vpc-flow-logs/*"]

 + This policy perevents : 
CloudTrail reading your other S3 data
CloudTrail deleting logs
VPC Flow Logs accessing CloudTrail logs
Any other AWS service writing to your bucket
 Public access to logs

+ IT  ALLOWS : 
Cloud  trail Writes logs to s3 
VPC flow logs to write flow logs 
we can read / write / delete logs 
so the scaner can access and read the logs 

For AWS-managed services (CloudTrail, Flow Logs), bucket policy is standard. -> That's why tehre is no need for IAM here 

## Complete Policy Visualization:
Bucket: my-logs-bucket
│
├── Policy Statements (4 total)
│   ├── Statement 1: CloudTrail "Can I check the door?"
│   ├── Statement 2: CloudTrail "I can put things in cloudtrail/ box"
│   ├── Statement 3: VPC Flow Logs "I can put things in vpc-flow-logs/ box"
│   └── Statement 4: VPC Flow Logs "Can I check the door?"
│
├── Folder: cloudtrail/
│   └── AWSLogs/account-id/CloudTrail/... (Auto-created by CloudTrail)
│
└── Folder: vpc-flow-logs/
    └── AWSLogs/vpc-flow-logs/... (Auto-created by VPC Flow Logs)