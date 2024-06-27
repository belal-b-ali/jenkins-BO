# import json
# import boto3
# import os
# import csv

# source_account_id = os.environ.get("SOURCE_ACCOUNT_ID", "592052461894")
# source_bucket_name = os.environ.get("SOURCE_BUCKET_NAME", "bali-test-bucket")

# destination_bucket_name = os.environ.get("DESTINATION_BUCKET_NAME", "bali-dest-bucket")

# s3_client = boto3.client('s3', aws_access_key_id=source_aws_access_key_id, aws_secret_access_key=source_aws_secret_access_key)
# s3_control_client = boto3.client('s3control', aws_access_key_id=source_aws_access_key_id, aws_secret_access_key=source_aws_secret_access_key, region_name='us-east-1')


# # def create_report_bucket(source_bucket):
# #     s3_client.create_bucket(
# #         Bucket=f"{source_bucket}-batch-operation-reports",
# #         CreateBucketConfiguration={
# #             'LocationConstraint': 'eu-west-1',
# #         },
# #     )

# def get_objects_from_prefix(bucket_name, prefix):
#     """
#     Retrieve all objects from a specific prefix in an S3 bucket.
    
#     Parameters:
#     - bucket_name (str): The name of the S3 bucket.
#     - prefix (str): The prefix to filter objects.
    
#     Returns:
#     - List of object keys (list of str).
#     """
#     paginator = s3_client.get_paginator('list_objects_v2')
#     page_iterator = paginator.paginate(Bucket=bucket_name, Prefix=prefix)
    
#     object_keys = []
#     for page in page_iterator:
#         if 'Contents' in page:
#             for obj in page['Contents']:
#                 if not obj['Key'].endswith('/'): 
#                     object_keys.append(obj['Key'])
    
#     return object_keys

# def upload_manifest_file(local_file_path, bucket):
#     # manifest_bucket_name = f'{bucket}-manifest-bucket'
#     # manifest_s3_key = 'manifest.json'

#     # Upload the manifest file
#     s3_client.upload_file(local_file_path, bucket, local_file_path)
#     # return manifest_bucket_name, manifest_s3_key

# def create_csv_manifest_file(source_bucket, filtered_objects):
#     manifest_file_path = f'bali-manifest/{source_bucket}-manifest.csv'
#     os.makedirs(os.path.dirname(manifest_file_path), exist_ok=True)

#     with open(manifest_file_path, 'w', newline='') as csvfile:
#         writer = csv.writer(csvfile)
#         writer.writerow(['Bucket', 'Key', 'VersionId'])
        
#         for obj in filtered_objects:
#             # Get the latest version of the object
#             response = s3_client.list_object_versions(Bucket=source_bucket, Prefix=obj)
#             versions = response.get('Versions', [])
#             if versions:
#                 latest_version = versions[0]
#                 writer.writerow([source_bucket, obj, latest_version['VersionId']])
#             else:
#                 # If no version is found, you might want to handle it differently
#                 print(f"No version found for {obj}")

#     return manifest_file_path


# def get_manifest_file_etag(manifest_bucket_name, manifest_s3_key):
#     s3_client.head_object(Bucket=manifest_bucket_name, Key=manifest_s3_key)['ETag']

# def create_batch_operation(etag):
#     source_bucket = "bali-test-bucket"
#     try:
#         res = s3_control_client.create_job(
#             AccountId=source_account_id,
#             ConfirmationRequired=False,
#             Operation={
#                 "S3ReplicateObject": {
#                     # "TargetResource": f"arn:aws:s3:::{destination_bucket_name}",
#                 }
#             },
#             Report={
#                 "Enabled": True,
#                 "Format": "Report_CSV_20180820",
#                 "Bucket": f"arn:aws:s3:::{source_bucket}-batch-operation-reports",
#                 "ReportScope": "AllTasks"
#             },
#             Manifest={
#                 "Spec": {
#                     "Format": "S3BatchOperations_JSON_20180820",
#                     "Fields": [
#                         "Bucket", "Key"
#                     ]
#                 },
#                 "Location": {
#                     "ObjectArn": f"arn:aws:s3:::bali-manifest/bali-manifest/bali-test-bucket-folder1-manifest.json",
#                     "ETag": etag
#                 }
#             },
#             Priority=10,
#             RoleArn=f"arn:aws:iam::{source_account_id}:role/bali-dest-bucketRole",
#             Description='update the format'
#         )
#         print("res:     ", res)
#     except Exception as e:
#         print(e)
#         # print("Error Code:", e.response['Error']['Code'])
#         # print("Error Message:", e.response['Error']['Message'])
#         # print("Error Response:", e.response)

# # create_batch_operation(manifest_etag)
# # create_report_bucket(source_bucket_name)
# # manifest_bucket_name, manifest_s3_key = upload_manifest_file(source_bucket_name, manifest_file_path)
# # create_manifest_bucket(source_bucket_name)
# # objects = get_objects_from_prefix(source_bucket_name, 'folder1')
# # manifest_file_path = create_csv_manifest_file(source_bucket_name, objects)
# # manifest_file_path = create_csv_manifest_file(source_bucket_name, filtered_objects, 'folder1')
# upload_manifest_file("bali-manifest/bali-test-bucket-manifest.csv", "bali-manifest")
# # manifest_etag = s3_client.head_object(Bucket="bali-manifest", Key="bali-manifest/bali-test-bucket-folder1-manifest.json")['ETag']
# # res = create_batch_operation(manifest_etag)


# ################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################
# import json
# import boto3
# import os
# import uuid

# source_account_id = os.environ.get("SOURCE_ACCOUNT_ID", "592052461894")
# source_bucket_name = os.environ.get("SOURCE_BUCKET_NAME", "bali-test-bucket")

# completion_report_bucket = os.environ.get("COMPLETION_REPORT_BUCKET", "bali-test-bucket-batch-operation-reports1")

# destination_bucket_name_1 = os.environ.get("DESTINATION_BUCKET_NAME", "bali-test-bucketv4")
# destination_bucket_name_2 = os.environ.get("DESTINATION_BUCKET_NAME", "bali-test-bucketv5")

# def get_iam_client():
#     try:
#         session = boto3.Session(
#             aws_access_key_id=source_aws_access_key_id,
#             aws_secret_access_key=source_aws_secret_access_key
#         )
#     except Exception as e:
#         print(">>>>>>> An Error ocurred <<<<<<<")
#         print(e)

#     # Create an IAM client
#     return  session.client('iam')

# def get_s3_client(aws_access_key_id, aws_secret_access_key):
#     try:
#         session = boto3.Session(
#             aws_access_key_id=aws_access_key_id,
#             aws_secret_access_key=aws_secret_access_key
#         )
#     except Exception as e:
#         print(">>>>>>> An Error ocurred <<<<<<<")
#         print(e)

#     # Create an S3 client
#     return  session.client('s3')

# def get_s3control_client(aws_access_key_id, aws_secret_access_key):
#     try:
#         boto3_session = boto3.Session(
#             aws_access_key_id=aws_access_key_id,
#             aws_secret_access_key=aws_secret_access_key
#         )
#     except Exception as e:
#         print(">>>>>>> An Error ocurred <<<<<<<")
#         print(e)

#     return boto3_session.client('s3control', region_name = boto3_session.region_name)

# def create_iam_role(role_name):
#     iam_client = get_iam_client()
#     try:
#         iam_client.create_role(
#             RoleName=role_name,
#             AssumeRolePolicyDocument=json.dumps({
#                 "Version": "2012-10-17",
#                 "Statement": [
#                     {
#                         "Effect": "Allow",
#                         "Principal": {
#                             "Service": ["s3.amazonaws.com", "batchoperations.s3.amazonaws.com"]
#                         },
#                         "Action": "sts:AssumeRole"
#                     }
#                 ]
#             }),
#         )
#     except Exception as e:
#         print(">>>>>>> An Error ocurred <<<<<<<")
#         print(e)


# def attach_policy_to_iam_role(role_name, policy_name, destination_bucket, source_bucket, completion_report_bucket):
#     iam_client = get_iam_client()

#     policy_document = {
#         "Version":"2012-10-17",
#         "Statement":[
#             {
#                 "Effect":"Allow",
#                 "Action":[
#                     "s3:GetReplicationConfiguration",
#                     "s3:ListBucket",
#                     "s3:PutInventoryConfiguration"
#                 ],
#                 "Resource": f"arn:aws:s3:::{source_bucket}"
#             },
#             {
#                 "Effect":"Allow",
#                 "Action":[
#                     "s3:GetObjectVersionForReplication",
#                     "s3:GetObjectVersionAcl",
#                     "s3:GetObjectVersionTagging",
#                     "s3:InitiateReplication"
#                 ],
#                 "Resource": f"arn:aws:s3:::{source_bucket}/*"
#             },
#             {
#                 "Effect":"Allow",
#                 "Action":[
#                     "s3:ReplicateObject",
#                     "s3:ReplicateDelete",
#                     "s3:ReplicateTags"
#                 ],
#                 "Resource": f"arn:aws:s3:::{destination_bucket}/*"
#             },
#             {
#                 "Effect":"Allow",
#                 "Action":[
#                     "s3:GetObject",
#                     "s3:GetObjectVersion",
#                     "s3:PutObject"
#                 ],
#                 "Resource": f"arn:aws:s3:::{completion_report_bucket}/*"
#             }
#         ]
#     }

#     try:
#         print(f"Attaching policy {policy_name}\n policy value {policy_document}\n to the IAM role {role_name}")
#         iam_client.put_role_policy(
#             RoleName=role_name,
#             PolicyName=policy_name,
#             PolicyDocument=json.dumps(policy_document)
#         )
#     except Exception as e:
#         print(">>>>>>> An Error ocurred <<<<<<<")
#         print(e)


# def add_bucket_policy(bucket_name, role_name, destination_aws_access_key_id, destination_aws_secret_access_key, source_account_id):
#     # Get the current bucket policy
#     s3_client = get_s3_client(destination_aws_access_key_id, destination_aws_secret_access_key)

#     try:
#         current_policy = json.loads(s3_client.get_bucket_policy(Bucket=bucket_name)['Policy'])
#     except:
#         current_policy = {'Statement': []}

#     # New policy statement
#     new_statement = [
#         {
#             "Sid":"Permissions on objects",
#             "Effect":"Allow",
#             "Principal":{
#                 "AWS":f"arn:aws:iam::{source_account_id}:role/{role_name}"
#             },
#             "Action":[
#                 "s3:ReplicateDelete",
#                 "s3:ReplicateObject",
#                 "s3:ReplicateTags"
#             ],
#             "Resource":f"arn:aws:s3:::{bucket_name}/*"
#         },
#         {
#             "Sid":"Permissions on bucket",
#             "Effect":"Allow",
#             "Principal":{
#                 "AWS":f"arn:aws:iam::{source_account_id}:role/{role_name}"
#             },
#             "Action": [
#                 "s3:List*",
#                 "s3:GetBucketVersioning",
#                 "s3:PutBucketVersioning"
#             ],
#             "Resource":f"arn:aws:s3:::{bucket_name}"
#         }
#     ]

#     # Add the new statement to the existing policy
#     current_policy['Statement'].extend(new_statement)

#     # Apply the updated policy to the bucket
#     try:
#         print(f"Adding bucket policy {current_policy} to the destination bucket {bucket_name}...")
#         s3_client.put_bucket_policy(
#             Bucket=bucket_name,
#             Policy=json.dumps(current_policy)
#         )
#     except Exception as e:
#         print(">>>>>>> An Error ocurred <<<<<<<")
#         print(e)


# def apply_replication_configuration(source_bucket_name, source_aws_access_key_id, source_aws_secret_access_key, source_account_id, role_name, destination_bucket_name, prefix):
#     s3_client = get_s3_client(source_aws_access_key_id, source_aws_secret_access_key)
#     replication_configuration={
#         'Role': f"arn:aws:iam::{source_account_id}:role/{role_name}",
#         'Rules': [
#             {
#                 'ID': f'ReplicationRule-{source_bucket_name}-{destination_bucket_name}',
#                 'Status': 'Enabled',
#                 'Prefix': prefix,
#                 'Destination': {
#                     'Bucket': f"arn:aws:s3:::{destination_bucket_name}",
#                     'StorageClass': 'STANDARD_IA'
#                 }
#             }
#         ]
#     }
#     try:
#         print(f"Applying replication configuration {replication_configuration} to the source bucket")
#         s3_client.put_bucket_replication(
#             Bucket=source_bucket_name,
#             ReplicationConfiguration=replication_configuration
#         )
#     except Exception as e:
#         print(">>>>>>> An Error ocurred <<<<<<<")
#         print(e)


# def create_batch_job_to_copy_existing_objects(source_aws_access_key_id, source_aws_secret_access_key, source_aws_account_id, source_bucket, report_bucket, role_name):
#     reportfolder = "report/"

#     token = str(uuid.uuid4())

#     cl = get_s3control_client(source_aws_access_key_id, source_aws_secret_access_key)

#     response = cl.create_job(
#         AccountId = source_aws_account_id,
#         ConfirmationRequired = False,
#         Operation = {
#             'S3ReplicateObject': {}
#         },
#         Report = {
#             'Bucket': f"arn:aws:s3:::{report_bucket}",
#             'Format': 'Report_CSV_20180820',
#             'Enabled': True,
#             'Prefix': reportfolder,
#             'ReportScope': 'AllTasks'
#         },
#         ClientRequestToken = token,
#         ManifestGenerator = {
#             'S3JobManifestGenerator': {
#                 'ExpectedBucketOwner': source_aws_account_id,
#                 'SourceBucket': f"arn:aws:s3:::{source_bucket}",
#                 'ManifestOutputLocation': {
#                     'ExpectedManifestBucketOwner': source_aws_account_id,
#                     'Bucket': f"arn:aws:s3:::{report_bucket}",
#                     'ManifestPrefix': 'manifest/',
#                     'ManifestEncryption': {
#                         'SSES3': {}
#                     },
#                     'ManifestFormat': 'S3InventoryReport_CSV_20211130'
#                 },
#                 'Filter': {
#                     'EligibleForReplication': True
#                 },
#                 'EnableManifestOutput': True
#             }
#         },
#         Priority = 1,
#         RoleArn = f"arn:aws:iam::{source_aws_account_id}:role/{role_name}"
#     )

#     print(response)

# print(">>>>>>> create_iam_role <<<<<<<<<")
# create_iam_role(f'replicationRoleFromBoto3_{destination_bucket_name_1}')
# # create_iam_role(f'replicationRoleFromBoto3_{destination_bucket_name_2}')

# print(">>>>>>> attach_policy_to_iam_role <<<<<<<<<")
# attach_policy_to_iam_role(f'replicationRoleFromBoto3_{destination_bucket_name_1}', f'policyFromBoto3_{destination_bucket_name_1}', destination_bucket_name_1, source_bucket_name, completion_report_bucket)
# # attach_policy_to_iam_role(f'replicationRoleFromBoto3_{destination_bucket_name_2}', f'policyFromBoto3_{destination_bucket_name_2}', destination_bucket_name_2, source_bucket_name, completion_report_bucket)

# print(">>>>>>> add_bucket_policy <<<<<<<<<")
# add_bucket_policy(destination_bucket_name_1, f'replicationRoleFromBoto3_{destination_bucket_name_1}', destination_aws_access_key_id, destination_aws_secret_access_key, source_account_id)
# # add_bucket_policy(destination_bucket_name_2, f'replicationRoleFromBoto3_{destination_bucket_name_2}', destination_aws_access_key_id, destination_aws_secret_access_key, source_account_id)

# print(">>>>>>> apply_replication_configuration <<<<<<<<<")
# apply_replication_configuration(source_bucket_name, source_aws_access_key_id, source_aws_secret_access_key, source_account_id, 'replicationRoleFromBoto3', destination_bucket_name_1, 'folder1/')

# print(">>>>>>> create_batch_job_to_copy_existing_objects <<<<<<<<<")
# create_batch_job_to_copy_existing_objects(source_aws_access_key_id, source_aws_secret_access_key, source_account_id, source_bucket_name, completion_report_bucket, f'replicationRoleFromBoto3_{destination_bucket_name_1}')
# ################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################

from time import sleep
import json
import boto3
import os
import uuid
import argparse

aws_access_key_id = os.environ.get("ACCOUNT_ACCESS_KEY")
aws_secret_access_key = os.environ.get("ACCOUNT_SECRET_KEY")
account_id = os.environ.get("ACCOUNT_ID", "592052461894")
bucket_name = os.environ.get("BUCKET_NAME", "bali-test-bucket")

completion_report_bucket = os.environ.get("COMPLETION_REPORT_BUCKET", "bali-test-bucket-batch-operation-reports1")

# destination_bucket_name_1 = os.environ.get("DESTINATION_BUCKET_NAME", "bali-test-bucketv6")
# destination_bucket_name_2 = os.environ.get("DESTINATION_BUCKET_NAME", "bali-test-bucketv7")

# def get_iam_client():
#     try:
#         session = boto3.Session(
#             aws_access_key_id=source_aws_access_key_id,
#             aws_secret_access_key=source_aws_secret_access_key
#         )
#     except Exception as e:
#         print(">>>>>>> An Error ocurred <<<<<<<")
#         print(e)

#     # Create an IAM client
#     return  session.client('iam')

# def get_s3_client(aws_access_key_id, aws_secret_access_key):
#     try:
#         session = boto3.Session(
#             aws_access_key_id=aws_access_key_id,
#             aws_secret_access_key=aws_secret_access_key
#         )
#     except Exception as e:
#         print(">>>>>>> An Error ocurred <<<<<<<")
#         print(e)

#     # Create an S3 client
#     return  session.client('s3')

# def create_iam_role(role_name):
#     iam_client = get_iam_client()
#     iam_client.create_role(
#         RoleName=role_name,
#         AssumeRolePolicyDocument=json.dumps({
#             "Version": "2012-10-17",
#             "Statement": [
#                 {
#                     "Effect": "Allow",
#                     "Principal": {
#                         "Service": ["s3.amazonaws.com", "batchoperations.s3.amazonaws.com"]
#                     },
#                     "Action": "sts:AssumeRole"
#                 }
#             ]
#         }),
#     )

# def attach_policy_to_iam_role(role_name, policy_name, destination_bucket, destination_bucket_2, source_bucket, completion_report_bucket):
#     print(f"Attaching policy to the IAM role in")
#     iam_client = get_iam_client()

#     policy_document = {
#         "Version":"2012-10-17",
#         "Statement":[
#             {
#                 "Effect":"Allow",
#                 "Action":[
#                     "s3:GetReplicationConfiguration",
#                     "s3:ListBucket",
#                     "s3:PutInventoryConfiguration"
#                 ],
#                 "Resource": f"arn:aws:s3:::{source_bucket}"
#             },
#             {
#                 "Effect":"Allow",
#                 "Action":[
#                     "s3:GetObjectVersionForReplication",
#                     "s3:GetObjectVersionAcl",
#                     "s3:GetObjectVersionTagging",
#                     "s3:InitiateReplication"
#                 ],
#                 "Resource": f"arn:aws:s3:::{source_bucket}/*"
#             },
#             {
#                 "Effect":"Allow",
#                 "Action":[
#                     "s3:ReplicateObject",
#                     "s3:ReplicateDelete",
#                     "s3:ReplicateTags"
#                 ],
#                 "Resource": [f"arn:aws:s3:::{destination_bucket}/*", f"arn:aws:s3:::{destination_bucket_2}/*"]
#             },
#             {
#                 "Effect":"Allow",
#                 "Action":[
#                     "s3:GetObject",
#                     "s3:GetObjectVersion",
#                     "s3:PutObject"
#                 ],
#                 "Resource": f"arn:aws:s3:::{completion_report_bucket}/*"
#             }
#         ]
#     }

#     iam_client.put_role_policy(
#         RoleName=role_name,
#         PolicyName=policy_name,
#         PolicyDocument=json.dumps(policy_document)
#     )

# def add_bucket_policy(bucket_name, role_name, destination_aws_access_key_id, destination_aws_secret_access_key, source_account_id):
#     print(f"Adding bucket policy to the destination bucket {bucket_name}...")
#     # Get the current bucket policy
#     s3_client = get_s3_client(destination_aws_access_key_id, destination_aws_secret_access_key)

#     try:
#         current_policy = json.loads(s3_client.get_bucket_policy(Bucket=bucket_name)['Policy'])
#     except:
#         current_policy = {'Statement': []}

#     # New policy statement
#     new_statement = [
#         {
#             "Sid":"Permissions on objects",
#             "Effect":"Allow",
#             "Principal":{
#                 "AWS":f"arn:aws:iam::{source_account_id}:role/{role_name}"
#             },
#             "Action":[
#                 "s3:ReplicateDelete",
#                 "s3:ReplicateObject",
#                 "s3:ReplicateTags"
#             ],
#             "Resource":f"arn:aws:s3:::{bucket_name}/*"
#         },
#         {
#             "Sid":"Permissions on bucket",
#             "Effect":"Allow",
#             "Principal":{
#                 "AWS":f"arn:aws:iam::{source_account_id}:role/{role_name}"
#             },
#             "Action": [
#                 "s3:List*",
#                 "s3:GetBucketVersioning",
#                 "s3:PutBucketVersioning"
#             ],
#             "Resource":f"arn:aws:s3:::{bucket_name}"
#         }
#     ]

#     # Add the new statement to the existing policy
#     current_policy['Statement'].extend(new_statement)

#     # Apply the updated policy to the bucket
#     try:
#         s3_client.put_bucket_policy(
#             Bucket=bucket_name,
#             Policy=json.dumps(current_policy)
#         )
#     except Exception as e:
#         print(e)
#         exit()

# def apply_replication_configuration(source_bucket_name, source_aws_access_key_id, source_aws_secret_access_key, source_account_id, role_name, destination_bucket_name_1, destination_bucket_name_2):
#     print("Applying replication configuration to the source bucket")
#     s3_client = get_s3_client(source_aws_access_key_id, source_aws_secret_access_key)

#     s3_client.put_bucket_replication(
#         Bucket=source_bucket_name,
#         ReplicationConfiguration={
#             'Role': f"arn:aws:iam::{source_account_id}:role/{role_name}",
#             'Rules': [
#                 {
#                     'ID': 'ReplicationRuleBucket4',
#                     'Status': 'Enabled',
#                     'Prefix': 'folder1/',
#                     'Destination': {
#                         'Bucket': f"arn:aws:s3:::{destination_bucket_name_1}",
#                         'StorageClass': 'STANDARD_IA'
#                     }
#                 }
#             ]
#         }
#     )

# def check_iam(role_name):
#     iam_client = get_iam_client()

#     try:
#         iam_client.get_role(RoleName=role_name)
#         return True
#     except Exception as e:
#         if e.response['Error']['Code'] == 'NoSuchEntity':
#             return False
#         else:
#             # If some other error occurred, you might want to handle it differently.
#             raise

def get_s3control_client(aws_access_key_id: str, aws_secret_access_key: str) -> boto3.client:
    """
    Create an S3 Control client with the provided AWS credentials.

    Args:
        aws_access_key_id (str): AWS access key ID.
        aws_secret_access_key (str): AWS secret access key.

    Returns:
        boto3.client: A boto3 S3 Control client.
    """
    try:
        boto3_session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )
    except Exception as e:
        print(e)

    return boto3_session.client('s3control', region_name = boto3_session.region_name)

def create_batch_job_to_copy_existing_objects(aws_access_key_id: str, aws_secret_access_key: str, aws_account_id: str, bucket: str, report_bucket: str, role_name: str) -> None:
    """
    Create a batch job to copy existing objects from the source bucket to the destination.

    Args:
        aws_access_key_id (str): Source AWS access key ID.
        aws_secret_access_key (str): Source AWS secret access key.
        aws_account_id (str): Source AWS account ID.
        bucket (str): Source bucket name.
        report_bucket (str): Report bucket name.
        role_name (str): Role name for the job.
    """
    reportfolder = "report/"

    token = str(uuid.uuid4())

    cl = get_s3control_client(aws_access_key_id, aws_secret_access_key)

    response = cl.create_job(
        AccountId = aws_account_id,
        ConfirmationRequired = False,
        Operation = {
            'S3ReplicateObject': {}
        },
        Report = {
            'Bucket': f"arn:aws:s3:::{report_bucket}",
            'Format': 'Report_CSV_20180820',
            'Enabled': True,
            'Prefix': reportfolder,
            'ReportScope': 'AllTasks'
        },
        ClientRequestToken = token,
        ManifestGenerator = {
            'S3JobManifestGenerator': {
                'ExpectedBucketOwner': aws_account_id,
                'SourceBucket': f"arn:aws:s3:::{bucket}",
                'ManifestOutputLocation': {
                    'ExpectedManifestBucketOwner': aws_account_id,
                    'Bucket': f"arn:aws:s3:::{report_bucket}",
                    'ManifestPrefix': 'manifest/',
                    'ManifestEncryption': {
                        'SSES3': {}
                    },
                    'ManifestFormat': 'S3InventoryReport_CSV_20211130'
                },
                'Filter': {
                    'EligibleForReplication': True
                },
                'EnableManifestOutput': True
            }
        },
        Priority = 1,
        RoleArn = f"arn:aws:iam::{aws_account_id}:role/{role_name}"
    )

    print(response)

# create_batch_job_to_copy_existing_objects(source_aws_access_key_id, source_aws_secret_access_key, source_account_id, source_bucket_name, completion_report_bucket, "IAMFromBoto3V14")

def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description='Create a batch job to copy existing objects.')
    # parser.add_argument('--source_aws_access_key_id', required=True, help='Source AWS access key ID')
    # parser.add_argument('--source_aws_secret_access_key', required=True, help='Source AWS secret access key')
    parser.add_argument('--aws_account_id', required=True, help='AWS account ID')
    parser.add_argument('--bucket', required=True, help='bucket name')
    parser.add_argument('--report_bucket', required=True, help='Report bucket name')
    parser.add_argument('--role_name', required=True, help='Role name for the job')

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    print(">>>>>")
    print(args)
    print(aws_access_key_id)
    print(aws_secret_access_key)
    print(">>>>>")
    # create_batch_job_to_copy_existing_objects(
    #     source_aws_access_key_id,
    #     source_aws_secret_access_key,
    #     args.source_aws_account_id,
    #     args.source_bucket,
    #     args.report_bucket,
    #     args.role_name
    # )
