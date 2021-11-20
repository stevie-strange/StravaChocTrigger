import logging
import json
import os

import azure.functions as func


def main(req: func.HttpRequest, msg: func.Out[func.QueueMessage]) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    # Extract the method of the request for further processing
    mode = req.method

    if (mode == 'GET'):
        logging.info("Running GET Method...") 
        
        # Verify token from Key Vault Access
        VERIFY_TOKEN = os.getenv('StravaVerifyToken')

        # Extracting the parameters
        hubmode = req.params.get('hub.mode')
        token = req.params.get('hub.verify_token')
        challenge = req.params.get('hub.challenge')

        logging.info("Parameters extracted")

        if (hubmode and token):

            if (hubmode == 'subscribe' and token == VERIFY_TOKEN):
                logging.info('WEBHOOK_VERIFIED')

                payload= {"hub.challenge": challenge}
                
                return func.HttpResponse(json.dumps(payload), mimetype="application/json", status_code=200)
            else:
                return func.HttpResponse(status_code=403)
    elif (mode == 'POST'):
        logging.info("Running POST Method...")
        eventdata = req.get_json()
        
        logging.info("Event Data:" + str(eventdata))

        # Identify the type of event
        aspectType = eventdata.get('aspect_type')
        objectType = eventdata.get('object_type')
        eventid = eventdata.get('object_id')

        if (aspectType == 'create' and objectType == 'activity'):
            logging.info("New activity detected.")

            try:
                msg.set(str(eventid))

                logging.info("Queue started: " + str(eventid))

                return func.HttpResponse(status_code=200) 
            except Exception as e:
                return func.HttpResponse(status_code=500)
        else:
            # Just confirm the webhook
            logging.info("No new activity - nothing to do! :-)")
            return func.HttpResponse(status_code=200)

    else:
        logging.info("Unsupported Method...") 
        return func.HttpResponse("Not allowed", status_code=403)            
