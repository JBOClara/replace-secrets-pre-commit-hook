from __future__ import annotations
from typing import Sequence
import argparse

import re
import os
import boto3
import glob
from ruamel.yaml import YAML
from botocore.exceptions import BotoCoreError, ClientError
import json
# Create a YAML object
yaml = YAML(typ='rt')
yaml.width = 10000
yaml.default_flow_style = False
yaml.preserve_quotes = True


def handle_exceptions(func):
    def wrapper(*args, **kwargs):
        locals_before = locals().copy()
        try:
            return func(*args, **kwargs)
        except (BotoCoreError, ClientError, ValueError) as e:
            locals_after = locals().copy()
            func_locals = {k: locals_after[k] for k in locals_after if k not in locals_before}
            print(f"Une exception s'est produite : {type(e).__name__}")
            print(f"Secret en erreur : \n {json.dumps(args[0], indent=4)}")
            print(f"Fichier en erreur : {args[2]}")
            print(str(e))
            return None
    return wrapper

def print_error_context(file_path, error_line_number, context=2):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Print lines before error
    for i in range(max(0, error_line_number - context - 1), error_line_number - 1):
        print(lines[i], end='')

    print('----> ', lines[error_line_number - 1], end='')

    # Print lines after error
    for i in range(error_line_number, min(len(lines), error_line_number + context)):
        print(lines[i], end='')


def filter_secrets_with_arn(value):
    # Pattern to match secrets with ARN
    pattern = re.compile(r'^ref\+awssecrets://arn:aws:secretsmanager:')

    # Return False if the value matches the pattern, True otherwise
    return not pattern.match(value)

@handle_exceptions
def replace_secrets_with_arn(data, sm_client, yaml_file, retry=None):
    try:
        if isinstance(data, dict):
            # Iterate over the items in the YAML file
            for key, value in data.items():
                # Check if the value starts with 'ref+awssecrets://'
                if isinstance(value, str) and value.startswith('ref+awssecrets://') and filter_secrets_with_arn(value):
                    # Extract the secret name
                    secret_line = re.search(r'(?P<proto>ref\+awssecrets://)(?!arn:aws:secretsmanager:)([^#\n]*)#?(?P<key>[^#\n]*)(#(?P<version>[^#\n]*))?', value)
                    secret_name = secret_line.group(2)

                    print(f"Remplacement du secret {secret_name} par son ARN dans le fichier YAML.")
                    # Get the secret value from AWS Secrets Manager
                    secret_description = sm_client.describe_secret(SecretId=secret_name)


                    # Replace the secret name with its ARN in the YAML file
                    data[key] = value.replace(secret_name, secret_description['ARN'])
                else:
                    replace_secrets_with_arn(value, sm_client, yaml_file)
        elif isinstance(data, list):
            for i in range(len(data)):
                replace_secrets_with_arn(data[i], sm_client, yaml_file)
    except (BotoCoreError, ClientError) as e:
        if type(e).__name__ == 'ResourceNotFoundException':
            raise ValueError(f"Le secret {secret_name} n'existe pas.")

# Get AWS credentials from environment variables
aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
aws_security_token = os.getenv('AWS_SECURITY_TOKEN')
aws_region = os.getenv('AWS_DEFAULT_REGION')
env = os.getenv('ENV')
# # show access key
# print(aws_access_key_id)

# # show begin of secret key and token
# print(aws_secret_access_key[:5])
# print(aws_security_token[:5])

# Create a session using your AWS credentials
session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    aws_session_token=aws_security_token,
    region_name=aws_region  # or your preferred region
)

# show caller-identity
sts_client = session.client('sts')
identity = sts_client.get_caller_identity()
# print(identity)

# Create a client for the AWS Secrets Manager
sm_client = session.client('secretsmanager')

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'values-base-path', nargs='1',
        help='Path to the values.yaml file',
    )
    args = parser.parse_args(argv)
    values_base_path = args.values_base_path[0]
    # Placeholder pattern
    # placeholder_pattern = '/dow/db/password/'
    yaml_files = glob.glob(f'{values_base_path}/{env}/*/*/values.yaml') + glob.glob(f'{values_base_path}/{env}/*/*/*-values.yaml')

    for yaml_file in yaml_files:

        try:
            # Load the YAML file
            with open(yaml_file, 'r') as file:
                data = yaml.load(file)

            # Replace secrets with ARN in the data
            if replace_secrets_with_arn(data, sm_client, yaml_file) is None:
                exit(1)

            if data is None or data == {None: {None: None}} or data == {None: None}:
                continue
            # Write the data back to the file
            with open(yaml_file, 'w') as file:
                yaml.dump(data, file)
        except AttributeError as e:
            print(f"Unmanaged attribute error : {e}")
            raise e
        except Exception as e:
            print(f"Erreur lors de l'analyse du fichier YAML : {e}")
            print("Veuillez vérifier la syntaxe de votre fichier YAML.")
            error_line_number = e.problem_mark.line
            print_error_context(yaml_file, error_line_number)
            exit(1)

if __name__ == '__main__':
    raise SystemExit(main())
