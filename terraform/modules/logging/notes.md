include_management_events = True ( fi cloudTrail )  

What are "management events"? These are the IMPORTANT security events:

Management Events (When true)                   |    Data Events (separate config)
----------------------------------------------- |------------------------------------
- IAM: CreateUser, DeleteUser, AttachPolicy     | - S3: GetObject, PutObject
- EC2: RunInstances, TerminateInstances         | - Lambda: InvokeFunction  
- S3: CreateBucket, DeleteBucket                | - DynamoDB: PutItem, Query
- Security Group: AuthorizeSecurityGroupIngress | 
- CloudTrail: CreateTrail, UpdateTrail          |


