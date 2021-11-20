import logging
import os
import time
import requests

import azure.functions as func
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from requests.models import Response

########## CONSTANTS ####################
# Split point of the 2 linear functions
CURVE_THRESHOLD = 175

# Slope & intercept of first linear function
F1_SLOPE = 12.57
F1_INTERCEPT = 0

# Slope & intercept of second linear function
F2_SLOPE = 12.06
F2_INTERCEPT = 91


# function to calculate the CHO consumption
def calculate_cho(slope, intercept, power, cho_list):
    
    # Calculate CHO consumption based on linear function
    cho = slope * power + intercept
                    
    # scaled down from CHO per day to 1 hour
    cho = cho/24

    # Add the calculated value to list
    cho_list.append(round(cho))

    # Scale down to recording intervall of 1s
    cho = cho/60/60
                    
    # Return the cho conspumtion per s
    return cho


# function to load & handle the strava tokens
def get_access_token():

    logging.info("Get access token....")

    # Prepare access to key vault
    keyVaultName = os.getenv('StravaKeyVault')
    KVUri = f"https://{keyVaultName}.vault.azure.net"
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=KVUri, credential=credential)

    # Read expiry date from key vault
    expiresSecret = client.get_secret("StravaTokenExpires")
    expiresDate = float(expiresSecret.value)

    # If access_token has expired then 
    # use the refresh_token to get the new access_token
    if expiresDate < time.time():

        logging.info("Access token has expired, requesting new token....")

        # Make strava auth call
        response = requests.post(
            'https://www.strava.com/oauth/token',
            data= {
                'client_id': os.getenv('StravaClientID'),
               'client_secret': os.getenv('StravaClientSecret'),
                'refresh_token': client.get_secret("StravaRefreshToken").value,
                'grant_type': 'refresh_token'
            }   
        ) 
        
        #logging.info("Return Code: " + str(response.status_code))
        #logging.info("URL: " + response.url)
        #logging.info("Response data: " + str(response.json()))

        if (response.status_code == requests.codes.ok):

            # Handle the new tokens and expire date
            new_strava_tokens = response.json()
            new_access_token = new_strava_tokens.get('access_token')
            new_expires_date = new_strava_tokens.get('expires_at')
            new_refresh_token = new_strava_tokens.get('refresh_token')

            logging.info("New tokens received, updating key vault...")

            # Update secrets
            client.set_secret("StravaRefreshToken", new_refresh_token)
            client.set_secret("StravaAccessToken", new_access_token)
            client.set_secret("StravaTokenExpires", new_expires_date)

            return new_access_token
        else:
            response.raise_for_status()    

    #return os.getenv('StravaAccessToken')
    return client.get_secret("StravaAccessToken").value



def main(msg: func.QueueMessage) -> None:
    logging.info('Python queue trigger function processed a queue item: %s',
                 msg.get_body().decode('utf-8'))

    # Get access token
    access_token = get_access_token()   

    #logging.info("Access Token: " + str(access_token))   

    logging.info('Reading activity data...')

    # Get single activity
    base_url='https://www.strava.com/api/v3/activities/'
    #activityID = str(6279628501)
    activityID = msg.get_body().decode('utf-8')
    url = base_url + activityID
    payload = {'access_token': access_token}
    response = requests.get(url, params=payload)

    # Check return code and proceed
    if (response.status_code != requests.codes.ok):
        response.raise_for_status()   

    data=response.json() 
    #logging.info("Response data: " + str(data)) 

    # Extract activity type
    activityType = data.get('type')

    # Only process defined activity types
    if activityType == 'Ride' or activityType == 'VirtualRide':
        
        # Get activity duration
        activityDuration = data.get('elapsed_time')

        logging.info("Load power data of activity...")
        # Get power data stream for 1 activity based on time domain
        url = base_url + activityID + '/streams'
        payload = {'access_token': access_token, 'keys': 'watts', 'key_by_type': 'true', 'series_type': 'time'}
        response = requests.get(url, params=payload)

        # Check return code and proceed
        if (response.status_code == requests.codes.ok):
            
            activityData=response.json()

            # Data processing - Reading the watt stream.
            logging.info("Extracting power data...")
            for element in activityData:
                if (element == 'watts'):
                    watt_data = activityData[element]
                    for element2 in watt_data:
                        if (element2 == 'data'):
                            watt_numbers = watt_data[element2]
        
            
            # Calculation of CHO consumption
            logging.info("Calculating CHO consumption...")
    
            # Reset CHO count
            total_cho = 0

            # List of all CHO values calculated
            cho_values = []

            for x in watt_numbers:
                # Reset power 
                current_power = 0

                # Extract the current power value
                current_power = x

                # validate the power information
                if current_power is not None:

                    # if the power value is below the threshold value apply the first formula
                    if current_power <= CURVE_THRESHOLD:
                    
                        # call function with linear function 1
                        total_cho = total_cho + calculate_cho(F1_SLOPE, F1_INTERCEPT, current_power, cho_values)

                        # Since the power value is above the threshold use the second formula
                    else:
                    
                        # call function with linear function 2
                        total_cho = total_cho + calculate_cho(F2_SLOPE, F2_INTERCEPT, current_power, cho_values)

            # Inform user about the results
            logging.info("CHO calculation finished. Updating strava activity...")

            # Update description of Strava activity
            url = base_url + activityID
            payload = {'access_token': access_token}
            body = {'description': 'Total carbohydrates burned (g): ' + str(round(total_cho)) + '\nCarbohydrates burned per hour (g): ' + str(round(total_cho / activityDuration * 60 * 60))}
            response = requests.put(url, params=payload, data=body)
            if (response.status_code != requests.codes.ok):
                response.raise_for_status()

            # Inform user about the results
            logging.info("Strava activity updated. Processing has finished.")
        else:
            response.raise_for_status()     

    else:
        logging.info("Unsupported activity type. Processing terminated")