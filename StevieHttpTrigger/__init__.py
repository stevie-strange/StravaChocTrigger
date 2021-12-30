"""main file for the queue trigger""" #pylint: disable=invalid-name
import logging
import json
import os

import azure.functions as func
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from azure.data.tables import TableClient
from azure.core.exceptions import ResourceExistsError


def init_key_vault():
    """Helper function to get access to Azure KeyVault"""

    # Prepare access to key vault
    key_vault_name = os.getenv('StravaKeyVault')
    key_vault_uri = f"https://{key_vault_name}.vault.azure.net"
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=key_vault_uri, credential=credential)

    return client


def main(req: func.HttpRequest,
        msg: func.Out[func.QueueMessage])-> func.HttpResponse:
    """Main function of the HTTPTrigger Function"""

    logging.info('Python HTTP trigger function processed a request.')

    # Extract the method of the request for further processing
    mode = req.method

    if mode == 'GET':
        logging.info("Running GET Method...")

        # Extracting the parameters
        hubmode = req.params.get('hub.mode')
        token = req.params.get('hub.verify_token')

        logging.info("Parameters extracted")

        if (hubmode and token):

            if (hubmode == 'subscribe' and token == os.getenv('StravaVerifyToken')):
                logging.info('WEBHOOK_VERIFIED')

                payload= {"hub.challenge": req.params.get('hub.challenge')}

                return func.HttpResponse(json.dumps(payload),
                                        mimetype="application/json",
                                        status_code=200)

    elif mode == 'POST':
        logging.info("Running POST Method...")
        eventdata = req.get_json()

        logging.info("Event Data: %s", str(eventdata))

        # Identify the type of event
        aspectType = eventdata.get('aspect_type')
        objectType = eventdata.get('object_type')

        if (aspectType == 'create' and objectType == 'activity'):
            logging.info("New activity detected.")

            # check azure table if eventid is already stored, means queue is already triggered.
            # If not stored yet, write eventif to azure table
            # and start the queue.
            try:

                # Prepare access to key vault
                vault_client = init_key_vault()

                # Get connection string from key vault
                connection_string = vault_client.get_secret("StravaConString").value
                table_client = TableClient.from_connection_string(conn_str=connection_string,
                                                                    table_name="status")

                # Get event id
                eventid = eventdata.get('object_id')

                data = {"Name": "Output message",
                        "PartitionKey": "message",
                        "RowKey": str(eventid)}

                # Insert new activity id into table
                table_client.create_entity(entity=data)

                # Start queue trigger
                msg.set(str(eventid))

                logging.info("Queue started: %s", str(eventid))

                return func.HttpResponse(status_code=200)

            except ResourceExistsError:
                logging.info("Processing already done for activity: %s", str(eventid))
                return func.HttpResponse(status_code=200)

            except Exception as e: #pylint: disable=broad-except
                logging.exception(e)
                return func.HttpResponse(status_code=500)
        else:
            # Just confirm the webhook
            logging.info("No new activity - nothing to do! :-)")
            return func.HttpResponse(status_code=200)

    logging.info("Unsupported Method...")
    return func.HttpResponse("Not allowed", status_code=403)
