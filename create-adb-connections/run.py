import base64
import json
import requests
from azure.identity import DefaultAzureCredential
from dotenv import load_dotenv
from services.asymmetrickeyencryptor import AsymmetricKeyEncryptor
import os
import random
import string


load_dotenv() 


GATEWAY_ID = os.getenv("GATEWAY_ID")
CLUSTER_HOSTNAME = os.getenv("CLUSTER_HOSTNAME")
CLUSTER_HTTP_PATH = os.getenv("CLUSTER_HTTP_PATH")
PERSONAL_ACCESS_TOKEN = os.getenv("PERSONAL_ACCESS_TOKEN")


def create_cloud_connection(connection_name):
    bearer_token = get_token()
    headers = {"Authorization": f"Bearer {bearer_token}"}
    body = {
        "connectivityType": "ShareableCloud",
        "displayName": connection_name,
        "connectionDetails": {
            "type": "Databricks",
            "creationMethod": "Databricks.Catalogs",
            "parameters": [
                {
                    "name": "host",
                    "value": CLUSTER_HOSTNAME,
                    "dataType": "Text"
                },
                {
                    "name": "httpPath",
                    "value": CLUSTER_HTTP_PATH,
                    "dataType": "Text"
                }
            ]
        },
        "privacyLevel": "Organizational",
        "credentialDetails": {
            "singleSignOnType": "None",
            "connectionEncryption": "NotEncrypted",
            "skipTestConnection": False,
            "credentials": {
                "credentialType": "Key",
                "key": PERSONAL_ACCESS_TOKEN
            }
        }
    }
    url = "https://api.fabric.microsoft.com/v1/connections"
    try:
        response = requests.post(url, headers=headers, json=body)
        response.raise_for_status()
        print(f"Connection '{connection_name}' created successfully.")
        print("Response:", response.json())
    except requests.exceptions.HTTPError as e:
        print(f"Failed to create connection: {e.response.text}")


def create_gw_connection(connection_name):
    bearer_token = get_token()
    headers = {"Authorization": f"Bearer {bearer_token}"}
    
    # Get the gateway public key
    try:
        public_key = get_gateway_public_key(bearer_token, GATEWAY_ID)
        if not public_key:
            print("Could not retrieve public key")
            return
        else:
            print("Retrieved public key successfully")
    except requests.exceptions.HTTPError as e:
        print(f"Error getting public key: {e.response.text}")
        return

    # Encrypt the credentials
    try:
        encrypted_pat = encrypt_credentials(bearer_token, public_key)
        if not encrypted_pat:
            print("Could not encrypt credentials")
            return
        else:
            print("Encrypted credentials successfully")
    except Exception as e:
        print(f"Error encrypting credentials: {e}")
        return



    body = {
        "connectivityType": "OnPremisesGateway",
        "gatewayId": GATEWAY_ID,
        "displayName": connection_name,
        "connectionDetails": {
            "type": "Databricks",
            "creationMethod": "Databricks.Catalogs",
            "parameters": [
                {
                    "name": "host",
                    "value": CLUSTER_HOSTNAME,
                    "dataType": "Text"
                },
                {
                    "name": "httpPath",
                    "value": CLUSTER_HTTP_PATH,
                    "dataType": "Text"
                }
            ]
        },
        "privacyLevel": "Organizational",
        "credentialDetails": {
            "singleSignOnType": "None",
            "connectionEncryption": "Encrypted",
            "skipTestConnection": False,
            "credentials": {
                "credentialType": "Key",
                "values": [
                    {
                        "gatewayId": GATEWAY_ID,
                        "encryptedCredentials": encrypted_pat
                    }
                ]
            }
        }
    }

    url = "https://api.fabric.microsoft.com/v1/connections"
    try:
        response = requests.post(url, headers=headers, json=body)
        response.raise_for_status()
        print(f"Connection '{connection_name}' created successfully.")
        print("Response:", response.json())
    except requests.exceptions.HTTPError as e:
        print(f"Failed to create connection: {e.response.text}")


def get_gateway_public_key(token, gateway_id):
    url = f"https://api.fabric.microsoft.com/v1/gateways/{gateway_id}"
    headers = {'Authorization': "Bearer " + token}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()['publicKey']
        else:
            print(f"Failed to get public key: {response.status_code} - {response.text}")
            return None
    except Exception as ex:
        print(f"Exception getting public key: {ex}")
        return None


def get_token():
    api = 'https://analysis.windows.net/powerbi/api/.default'
    try:
        auth = DefaultAzureCredential()
        access_token = auth.get_token(api)
        return access_token.token
    except Exception as ex:
        print(f"Exception getting token: {ex}")
        return None

def serialize_credentials(credential):
    serialized_credentials = '{\'credentialData\':[{\'name\':\'key\',\'value\':\'' + credential.encode('unicode_escape').decode() + '\'}]}'
    return serialized_credentials

def encrypt_credentials(access_token, public_key):
    ''' Encrypts the credentials for datasource '''

    try:
      # Serialize credentials for encryption
        serialized_credentials = serialize_credentials(PERSONAL_ACCESS_TOKEN)
        

        # Encrypt the credentials Asymmetric Key Encryption
        asymmetric_encryptor_service = AsymmetricKeyEncryptor(public_key)
        encrypted_credentials_string = asymmetric_encryptor_service.encode_credentials(serialized_credentials)
        
        return encrypted_credentials_string

    except Exception as ex:
        return json.dumps({'errorMsg': str(ex)}), 500


def main() -> None:

    arguments = os.sys.argv
    if len(arguments) < 2:
        print("Please provide at least one argument: 'cloud' or 'gateway'")
        return
    mode = arguments[1].lower()
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
    connection_name = arguments[2] if len(arguments) > 2 else f"MyConnection{random_suffix}"
    
    if mode not in ['cloud', 'gateway']:
        print("Invalid argument. Please use 'cloud' or 'gateway'")
        return  
    if mode == 'cloud':
        print("Creating cloud connection...")
        create_cloud_connection(connection_name)
    else:
        create_gw_connection(connection_name)


if __name__ == "__main__":
    main()