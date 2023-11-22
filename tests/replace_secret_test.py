from __future__ import annotations

from unittest.mock import patch, MagicMock
from claranet_hooks.replace_secret import replace_secrets_with_arn, filter_secrets_with_arn

def test_filter_secrets_with_arn():
    assert filter_secrets_with_arn('ref+awssecrets://arn:aws:secretsmanager:') == False
    assert filter_secrets_with_arn('ref+awssecrets://secret_name') == True

@patch('replace_secret.boto3')
def test_replace_secrets_with_arn(mock_boto3):
    mock_sm_client = MagicMock()
    mock_boto3.Session().client.return_value = mock_sm_client
    mock_sm_client.describe_secret.return_value = {'ARN': 'arn:aws:secretsmanager:secret_name'}

    data = {'key': 'ref+awssecrets://secret_name'}
    replace_secrets_with_arn(data, mock_sm_client, 'yaml_file')
    assert data['key'] == 'ref+awssecrets://arn:aws:secretsmanager:secret_name'

    data = ['ref+awssecrets://secret_name']
    replace_secrets_with_arn(data, mock_sm_client, 'yaml_file')
    assert data[0] == 'ref+awssecrets://arn:aws:secretsmanager:secret_name'
