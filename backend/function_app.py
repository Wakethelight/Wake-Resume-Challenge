import azure.functions as func
import os
import logging
import json
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.data.tables import TableServiceClient


app = func.FunctionApp()

def get_secret(secret_name):
    # Get the Key Vault URL from the environment variable
    KEY_VAULT_URL = os.environ["KEY_VAULT_URL", "https://primary-wow-vault.vault.azure.net/"]
    
    # Create a SecretClient using DefaultAzureCredential
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)
    secret = client.get_secret(secret_name)
    # Retrieve the secret value
    return secret.value

@app.function_name(name="VisitorCounter")
@app.route(route="VisitorCounter", auth_level=func.AuthLevel.ANONYMOUS)

def VisitorCounter(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    try:
        #Get keyvault url and secret names from environment variables
        KEY_VAULT_URL = os.environ.get["KEY_VAULT_URL"]
        table_connection_string_secret_name = os.environ.get("COSMOS_DB_CONNECTION_STRING_SECRET")
        table_name = "TablesDB"
        partition_key = "VisitorCount"
        row_key = "count"

        if not KEY_VAULT_URL or not table_connection_string_secret_name:
            logging.error("Key Vault URL or Cosmos DB Table connection string secret is not set in environment variables.")
            return func.HttpResponse(
                "Key Vault URL, Cosmos DB URL, or Cosmos DB Key is not set in environment variables.", 
                status_code=500
            )
        
        # Get the connection string from Key Vault
        table_connection_string = get_secret(KEY_VAULT_URL, table_connection_string_secret_name)

        #Initialize the TableServiceClient
        table_service_client = TableServiceClient.from_connection_string(conn_str=table_connection_string)
        table_client = table_service_client.get_table_client(table_name=table_name)

        try:
            # Retrieve the entity from the table
            entity = table_client.get_entity(partition_key=partition_key, row_key=row_key)
            visitor_count = entity["count"] + 1
        except Exception as e:
            # If the entity does not exist, initialize the visitor count to 1
            logging.info(f"Error retrieving entity: {e}. Initializing visitor count to 1.")
            visitor_count = 1
       #update or create entity
        entity = {
            "PartitionKey": partition_key,
            "RowKey": row_key,
            "count": visitor_count
        }
        table_client.upsert_entity(entity=entity)

        #create json response
        response_data = {"VisitorCount": visitor_count}
        response_json = json.dumps(response_data)

        return func.HttpResponse(
            response_json,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(f"Error processing request: {e}")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            mimetype="application/json",
            status_code=500
        )