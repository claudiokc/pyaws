import os
import inspect
import subprocess
import boto3
from botocore.exceptions import ClientError, ProfileNotFound
from pyaws.utils import stdout_message
from pyaws import logger

try:
    from pyaws.core.oscodes_unix import exit_codes
    splitchar = '/'     # character for splitting paths (linux)
except Exception:
    from pyaws.core.oscodes_win import exit_codes    # non-specific os-safe codes
    splitchar = '\\'    # character for splitting paths (window


DEFAULT_REGION = os.environ['AWS_DEFAULT_REGION'] or 'us-east-1'


def _profile_prefix(profile, prefix='gcreds'):
    """
    Summary:
        Determines if temporary STS credentials provided via
        local awscli config;
        - if yes, returns profile with correct prefix
        - if no, returns profile (profile_name) unaltered
        - Note:  Caller is parse_profiles(), Not to be called directly
    Args:
        profile (str): profile_name of a valid profile from local awscli config
        prefix (str): prefix prepended to profile containing STS temporary credentials
    Returns:
        awscli profilename, TYPE str
    """

    stderr = ' 2>/dev/null'
    tempProfile = prefix + '-' + profile

    try:
        if subprocess.check_output(
            'aws configure get profile.{profile}.aws_access_key_id {stderr}'.format(
                profile=profile, stderr=stderr)):
            return profile
        elif subprocess.check_output(
            'aws configure get profile.{tempProfile}.aws_access_key_id {stderr}'.format(
                tempProfile=tempProfile, stderr=stderr)):
            return tempProfile
    except Exception as e:
        logger.exception(
            '{i}: Unknown error while interrogating local awscli config: {e}'.format(
                i=inspect.stack()[0][3], e=e))
        raise
    return None


def parse_profiles(profiles):
    """
    Summary:
        Parse awscli profile_names given as parameter in 1 of 2 forms:
            1. single profilename given
            2. list of profile_names
        Also, function prepends profile_name(s) with a prefix when it detects
        profile_name refers to temp credentials in the local awscli configuration
    Args:
        profiles (str or file):  Profiles parameter can be either:
            - a single profile_name (str)
            - a file containing multiple profile_names, 1 per line
    Returns:
        - list of awscli profilenames, TYPE: list
        OR
        - single profilename, TYPE: str
    """

    profile_list = []

    try:
        if isinstance(profiles, list):
            return [_profile_prefix(x.strip()) for x in profiles]
        elif os.path.isfile(profiles):
            with open(profiles) as f1:
                for line in f1:
                    profile_list.append(_profile_prefix(line.strip()))
        else:
            return _profile_prefix(profiles.strip())
    except Exception as e:
        logger.exception(
            '{i}: Unknown error while converting profile_names from local awscli config: {e}'.format(
                i=inspect.stack()[0][3], e=e))
        raise
    return profile_list


def boto3_session(service, region=DEFAULT_REGION, profile=None):
    """
    Summary:
        Establishes boto3 sessions, client
    Args:
        :service (str): boto3 service abbreviation ('ec2', 's3', etc)
        :profile (str): profile_name of an iam user from local awscli config
        :region (str):  AWS region code, optional

    Returns:
        client (boto3 object)

    """
    fx = inspect.stack()[0][3]

    try:

        if (not profile or profile == 'default') and service != 'iam':
            return boto3.client(service, region_name=region)

        elif (not profile or profile == 'default') and service == 'iam':
            return boto3.client(service)

        elif profile and profile != 'default':
            session = boto3.Session(profile_name=profile)
            return session.client(service, region_name=region)

    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            logger.warning(
                '{}: Invalid credentials used by profile user {}'.format(fx, profile or 'default')
            )

        elif e.response['Error']['Code'] == 'ExpiredToken':
            logger.info(
                '%s: Expired temporary credentials detected for profile user (%s) [Code: %d]'
                % (fx, profile, exit_codes['EX_CONFIG']['Code']))

    except ProfileNotFound:
        msg = ('{}: Profile name {} was not found in your local config.'.format(fx, profile))
        stdout_message(msg, 'WARN')
        logger.warning(msg)
        return None
    return boto3.client(service, region_name=region)


def authenticated(profile):
    """
        Tests generic authentication status to AWS Account

    Args:
        :profile (str): iam user name from local awscli configuration

    Returns:
        TYPE: bool, True (Authenticated)| False (Unauthenticated)

    """
    try:
        sts_client = boto3_session(service='sts', profile=profile)
        httpstatus = sts_client.get_caller_identity()['ResponseMetadata']['HTTPStatusCode']
        if httpstatus == 200:
            return True

    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            logger.warning(
                '%s: Invalid credentials to authenticate for profile user (%s). Exit. [Code: %d]'
                % (inspect.stack()[0][3], profile, exit_codes['EX_NOPERM']['Code']))

        elif e.response['Error']['Code'] == 'ExpiredToken':
            logger.info(
                '%s: Expired temporary credentials detected for profile user (%s) [Code: %d]'
                % (inspect.stack()[0][3], profile, exit_codes['EX_CONFIG']['Code']))

        else:
            logger.exception(
                '%s: Unknown Boto3 problem. Error: %s' %
                (inspect.stack()[0][3], e.response['Error']['Message']))
    except Exception as e:
        fx = inspect.stack()[0][3]
        logger.exception('{}: Unknown error: {}'.format(fx, e))
        return False
    return False


def client_wrapper(service, profile='default', region=DEFAULT_REGION):
    """
    Summary.

        Single caller boto3 service wrapper. Instantiates client object while
        using temporary credientials for profile_name, if available in
        local configuration. Tests authentication prior to returning any
        client object.

    Args:
        :service (str): boto3 service abbreviation ('ec2', 's3', etc)
        :profile (str): profile_name of an iam user from local awscli config
        :region (str):  AWS region code, optional

    Returns:
        client (boto3 object)

    """
    profile_name = _profile_prefix(profile)

    try:

        if authenticated(profile_name):
            return boto3_session(service=service, profile=profile_name, region=region)

    except ClientError as e:
        logger.exception(
            "%s: Unknown boto3 failure while establishing session (Code: %s Message: %s)" %
            (inspect.stack()[0][3], e.response['Error']['Code'],
             e.response['Error']['Message'])
        )
    return None
