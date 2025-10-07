This script has an example for creating an Azure Databricks Connection in Fabric. 
It has options for creating a cloud connection or a gateway connection.

To run:
1. Download the code or clone the repo
2. Create a .env file with the following credentials
    CLUSTER_HOSTNAME = "<Your ADB cluster hostname>"
    CLUSTER_HTTP_PATH = "<Your ADB cluster http host path>"
    PERSONAL_ACCESS_TOKEN = "<Your ADB personal access token>"
    GATEWAY_ID = "<The Id of the on-premises gateway>"
3. pip install -r requirements.txt
4. python run.py <mode> <connection_name>
   1. mode is either "cloud" or "gateway"
   2. connection_name is the name of your connection. If none, the script will create a random name