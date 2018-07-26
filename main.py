import boto3
import json
import sys
import os
import re
import copy
from botocore.exceptions import ClientError
import requests
import time
# --------------GLOBALS------------------
ACCT_SAND1 = '{INSERT ACCT1ID}'
ACCT_SAND2 = '{INSERT ACCT2ID}'
ACCT_SAND3 = '{INSERT ACCT3ID}'
USER_ACCTS = [ACCT_SAND1, ACCT_SAND2]
BUCKET_ACCTS = [ACCT_SAND1]
OBJECT_ACCTS = [ACCT_SAND1, ACCT_SAND2, ACCT_SAND3]
ACCT_NAMES = {ACCT_SAND1: 'sameacct', ACCT_SAND2: 'crossacct', ACCT_SAND3: 'thirdacct'}
ACCT_DISPLAY_NAMES = {
    ACCT_SAND1: '1st Acct',
    ACCT_SAND2: '2nd Acct',
    ACCT_SAND3: '3rd Acct',
    'unauth': 'Unauth User'
}

# ----User Policies---------------
user_policy_allow = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "*"
    }]
}

user_policy_deny = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Deny",
        "Action": "s3:GetObject",
        "Resource": "*"
    }]
}

# ----Bucket Policies---------------
base_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Allow anyone to put objects",
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["s3:PutObject", "s3:PutObjectAcl", "s3:DeleteObject"],
            "Resource":["arn:aws:s3:::*"]
        }
    ]
}

# these are bucket policy statements appended onto the base policy
allow_any_statement = {
    "Sid": "Allow s3 get object",
    "Effect": "Allow",
    "Principal": "*",
    "Action": ["s3:GetObject"],
    "Resource": ["arn:aws:s3:::*"]
}

allow_calling_accounts_statement = {
    "Sid": "Allow s3 get object",
    "Effect": "Allow",
    "Principal": {"AWS": ["arn:aws:iam::{}:root".format(ACCT_SAND1), "arn:aws:iam::{}:root".format(ACCT_SAND2)]},
    "Action": ["s3:GetObject"],
    "Resource": ["arn:aws:s3:::*"]
}

deny_statement = {
    "Sid": "Deny s3 get object",
    "Effect": "Deny",
    "Principal": "*",
    "Action": ["s3:GetObject"],
    "Resource": ["arn:aws:s3:::*"]
}

USER_POLICIES = {'none': None, 'allow': user_policy_allow, 'deny': user_policy_deny}
BUCKET_POLICIES = {'none': None, 'allow-any': allow_any_statement, 'allow-calling-accounts': allow_calling_accounts_statement, 'deny': deny_statement}
# we found changing the bucket acl had no effect
BUCKET_ACLS = ['private']
OBJECT_ACLS = ['private', 'public-read', 'authenticated-read', 'bucket-owner-read']


# ------CLASSES---------------------
class User:
    def __init__(self, acct_id, user_policy, session):
        self.acct_id = acct_id
        self.user_policy = user_policy
        self.session = session


class Object:
    def __init__(self, bucket_acct_id, bucket_policy, bucket_acl, object_owner, object_acl, bucket_name, object_key):
        # identification for this script
        self.bucket_acct_id = bucket_acct_id
        self.bucket_policy = bucket_policy
        self.bucket_acl = bucket_acl
        self.object_owner = object_owner
        self.object_acl = object_acl

        # s3 identification for s3
        self.object_key = object_key
        self.bucket_name = bucket_name


account_sessions = {}


def create_session(acct_id):
    # cache account sessions for performance
    if acct_id not in account_sessions:

        print('CREATING Session... {}'.format(acct_id))
        sts = boto3.client('sts')
        credentials = sts.assume_role(
            RoleArn='arn:aws:iam::{}:role/trek10-kernel'.format(acct_id),
            RoleSessionName='s3blogpost'
        )['Credentials']
        # create session
        account_sessions[acct_id] = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )

    return account_sessions[acct_id]


def create_user(session, policy):   # session controls the account that the user is created in
    user_name = 'trek10-s3blogpost-{}'.format(policy)
    print('CREATING USER: {}...'.format(user_name))
    client = session.client('iam')

    # create user
    response = client.create_user(UserName=user_name)

    # attach in line policies
    if USER_POLICIES[policy] is not None:
        response = client.put_user_policy(PolicyDocument=json.dumps(USER_POLICIES[policy]), PolicyName='s3blogpost', UserName=user_name)

    # create an access key for the user
    print('CREATING USER ACCESS KEY...')
    response = client.create_access_key(UserName=user_name)
    access_key_id = response['AccessKey']['AccessKeyId']
    secret_access_key = response['AccessKey']['SecretAccessKey']

    # create session
    return boto3.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)


def create_bucket(session, bucket_acl, bucket_policy, acct_id):
    bucketName = 'trek10-s3blogpost-{}-{}-{}'.format(ACCT_NAMES[acct_id], bucket_acl, bucket_policy)
    print('CREATING BUCKET: {}...'.format(bucketName))
    client = session.client('s3')

    # create bucket
    response = client.create_bucket(ACL=bucket_acl, Bucket=bucketName)

    # every bucket gets a base policy with put permision
    this_policy = copy.deepcopy(base_policy)
    # update resource value to be this bucket
    this_policy['Statement'][0]["Resource"][0] = 'arn:aws:s3:::{}/*'.format(bucketName)

    # if bucket needs additional policy, append statement
    if BUCKET_POLICIES[bucket_policy] is not None:
        # update resource value to be this bucket
        BUCKET_POLICIES[bucket_policy]["Resource"][0] = 'arn:aws:s3:::{}/*'.format(bucketName)
        # append statement
        this_policy['Statement'].append(BUCKET_POLICIES[bucket_policy])

    # attach policy
    print('CREATING BUCKET POLICY...')
    response = client.put_bucket_policy(Bucket=bucketName, ConfirmRemoveSelfBucketAccess=True, Policy=json.dumps(this_policy))


def create_object(session, object_acl, bucket_acl, bucket_policy, object_acct_id, bucket_acct_id):
    bucket_name = 'trek10-s3blogpost-{}-{}-{}'.format(ACCT_NAMES[bucket_acct_id], bucket_acl, bucket_policy)
    object_key = 'object-{}-{}-s3blogpost.txt'.format(ACCT_NAMES[object_acct_id], object_acl)
    print('CREATING OBJECT...')
    client = session.client('s3')

    response = client.put_object(ACL=object_acl, Body=open('./sampleFile.txt', 'rb'), Bucket=bucket_name, Key=object_key)
    return Object(
        bucket_acct_id,
        bucket_policy,
        bucket_acl,
        object_acct_id,
        object_acl,
        bucket_name,
        object_key
    )


def delete_user(session, policy):
    userName = 'trek10-s3blogpost-{}'.format(policy)
    print('DELETING USER: {}...'.format(userName))
    iam = session.resource('iam')
    user = iam.User(userName)

    print('DELETING POLICY...')
    for policy in user.policies.all():
        policy.delete()

    print('DELETING USER ACCESS KEY...')
    for key in user.access_keys.all():
        key.delete()

    print('DELETING USER...')
    user.delete()


def delete_bucket(session, bucket_acl, bucket_policy, bucket_acct_id):
    bucketName = 'trek10-s3blogpost-{}-{}-{}'.format(ACCT_NAMES[bucket_acct_id], bucket_acl, bucket_policy)
    print('DELETING BUCKET: {}...'.format(bucketName))
    client = session.client('s3')

    response = client.delete_bucket(Bucket=bucketName)


def delete_object(session, object_acl, bucket_acl, bucket_policy, object_acct_id, bucket_acct_id):
    bucketName = 'trek10-s3blogpost-{}-{}-{}'.format(ACCT_NAMES[bucket_acct_id], bucket_acl, bucket_policy)
    print('DELETING OBJECT...')
    client = session.client('s3')

    response = client.delete_object(Bucket=bucketName, Key='object-{}-{}-s3blogpost.txt'.format(ACCT_NAMES[object_acct_id], object_acl))


def deploy():
    users = []
    # -----create users-----
    for acct_id in USER_ACCTS:
        acct_session = create_session(acct_id)
        for policy in USER_POLICIES:
            users.append(User(
                acct_id,
                policy,
                create_user(acct_session, policy)
            ))

    # -----create buckets and objects-----
    s3objects = []
    for bucket_acct_id in BUCKET_ACCTS:
        bucket_acct_session = create_session(bucket_acct_id)
        for bucket_acl in BUCKET_ACLS:
            for bucket_policy in BUCKET_POLICIES:
                create_bucket(bucket_acct_session, bucket_acl, bucket_policy, bucket_acct_id)

                for object_acct_id in OBJECT_ACCTS:
                    object_acct_session = create_session(object_acct_id)
                    for object_acl in OBJECT_ACLS:
                        s3objects.append(create_object(object_acct_session, object_acl, bucket_acl, bucket_policy, object_acct_id, bucket_acct_id))
    return users, s3objects


def delete():
    # -----delete users-----
    for acct_id in USER_ACCTS:
        acct_session = create_session(acct_id)
        for policy in USER_POLICIES:
            delete_user(acct_session, policy)

    # -----delete buckets + objects-----
    for bucket_acct_id in BUCKET_ACCTS:
        for bucket_acl in BUCKET_ACLS:
            for bucket_policy in BUCKET_POLICIES:
                # delete objects
                for object_acct_id in OBJECT_ACCTS:
                    object_acct_session = create_session(object_acct_id)
                    for object_acl in OBJECT_ACLS:
                        delete_object(object_acct_session, object_acl, bucket_acl,
                                      bucket_policy, object_acct_id, bucket_acct_id)

                # delete bucket
                bucket_acct_session = create_session(bucket_acct_id)
                delete_bucket(bucket_acct_session, bucket_acl,
                              bucket_policy, bucket_acct_id)


def test(users, s3objects):
    results = []  # tuple of user object, s3object object, and result
    # test every user
    for user in users:

        if (user.session is not None):
            client = user.session.client('s3')
        else:
            client = None

        # attempt to get every object
        for object in s3objects:
            print 'Testing: getting from {}/{}'.format(object.bucket_name, object.object_key)
            if client is not None:
                try:
                    response = client.get_object(Bucket=object.bucket_name, Key=object.object_key)
                    results.append((user, object, 'Success'))
                except ClientError as e:
                    results.append((user, object, e.response['Error']['Code']))
            else:
                r = requests.get('https://s3.amazonaws.com/{}/{}'.format(object.bucket_name, object.object_key))
                if r.status_code == 200:
                    results.append((user, object, 'Success'))
                elif r.status_code == 403:
                    results.append((user, object, 'AccessDenied'))
                elif r.status_code == 404:
                    results.append((user, object, 'NotFound'))
                else:
                    results.append((user, object, r.status_code))
    return results

def filterResults(results):
    # remove some duplicated entries
    # account1 getting from bucket in account1 with object owned by account2 is same as account1 getting from bucket in account1 with object owned by account3
    results = [r for r in results if (r[0].acct_id != ACCT_SAND1) or (r[1].object_owner != ACCT_SAND3)]

    # unauthenticated getting from bucket in account1 with object owned by account2 is same as unauthenticated getting from bucket in account1 with object owned by account3
    results = [r for r in results if r[0].acct_id != 'unauth' or r[1].object_owner != ACCT_SAND3]

    return results


def writeResults(results):
    with open('output/results.txt', 'w') as file:
        # heading
        file.write('User Account, User Policy, Bucket Policy, Object Owner Account, Object ACL, Caller owns bucket, Caller owns object, bucket owner owns object, Authenticated User, Has Access\n')
        # write each result
        for result in results:
            file.write(','.join([str(x) for x in [
                ACCT_DISPLAY_NAMES[result[0].acct_id],
                result[0].user_policy,
                result[1].bucket_policy,
                ACCT_DISPLAY_NAMES[result[1].object_owner],
                result[1].object_acl,
                'Yes' if result[0].acct_id == result[1].bucket_acct_id else 'No',
                'Yes' if result[0].acct_id == result[1].object_owner else 'No',
                'Yes' if result[1].bucket_acct_id == result[1].object_owner else 'No',
                'Yes' if result[0].acct_id != 'unauth' else 'No',
                result[2]
            ]]))
            file.write('\n')


if __name__ == "__main__":
    if len(sys.argv) == 2:
        delete()
    users, s3Objects = deploy()
    # add unauthenticated user
    users.append(User('unauth', 'none', None))

    results = test(users, s3Objects)
    delete()
    results = filterResults(results)
    writeResults(results)