"""main file for the queue trigger""" #pylint: disable=invalid-name
import logging
import os
import time
import requests

import azure.functions as func
import numpy as np
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

# Base Strava URL for activities
BASE_URL ='https://www.strava.com/api/v3/activities/'



def calc_cho(power):
    """function to calculate CHO consumption based on e function"""

    # reset CHO counter
    cho = 0

    # process the complete array
    for x in power:
        # CHO consumption is 0 beyond that wattage
        #if x < 275:
        if x is not None:
            # calculate CHO consumption in grams per hour
            y= 24.4817243 - 0.358447879 * x + 0.00708969851 * x**2 - 0.00000982862627 * x**3

            # Scale result down to recording interval of 1s
            y = y/60/60

             # Add value to the total consumption
            cho = cho + y

    return cho


# Calculate fat consumption based on the power
def calculate_fat(power):
    """function to calculate the fat consumption"""

    # reset fat counter
    fat = 0

    # process the complete array
    for x in power:
        if x is not None and x > 0:
            # calculate fat consumption in grams per hour
            y = 9.92211011 + 0.20866082 * x - 0.0000796973456 * x**2 - 0.00000305255098 * x**3
            
            # Scale result down to recording interval of 1s
            y = y/60/60

            # Add value to the total consumption
            fat = fat + y

    return fat


def calculate_cho(slope, intercept, power, cho_list):
    """function to calculate the CHO consumption"""

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


def get_access_token():
    """function to load & handle the strava tokens"""

    logging.info("Get access token....")

    # Prepare access to key vault
    key_vault_name = os.getenv('StravaKeyVault')
    key_vault_uri = f"https://{key_vault_name}.vault.azure.net"
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=key_vault_uri, credential=credential)

    # Read expiry date from key vault
    expires_secret = client.get_secret("StravaTokenExpires")
    expires_date = float(expires_secret.value)

    # If access_token has expired then
    # use the refresh_token to get the new access_token
    if expires_date < time.time():

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

        # proceed if request was successfull
        if response.status_code == requests.codes.ok: #pylint: disable=no-member

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

        # Raise exception since reponse was not ok.
        response.raise_for_status()

    return client.get_secret("StravaAccessToken").value



def main(msg: func.QueueMessage) -> None:
    """Main function"""

    logging.info('Python queue trigger function processed a queue item: %s',
                 msg.get_body().decode('utf-8'))

    # Get access token
    access_token = get_access_token()

    logging.info('Reading activity data...')

    activity_id = msg.get_body().decode('utf-8')
    response = requests.get(BASE_URL+activity_id, params={'access_token': access_token})

    # Check return code and proceed
    if response.status_code != requests.codes.ok: #pylint: disable=no-member
        response.raise_for_status()

    data=response.json()

    # Only process defined activity types
    if data.get('type') in ('Ride', 'VirtualRide'):

        # Get activity duration
        activity_duration = data.get('elapsed_time')

        logging.info("Load power data of activity...")
        # Get power data stream for 1 activity based on time domain
        payload = {'access_token': access_token,
                    'keys': 'watts',
                    'key_by_type': 'true',
                    'series_type': 'time'}

        response = requests.get(BASE_URL+activity_id+'/streams', params=payload)

        # Check return code and proceed
        if response.status_code == requests.codes.ok: #pylint: disable=no-member

            activity_data=response.json()

            # Data processing - Reading the watt stream.
            logging.info("Extracting power data...")

            watt_data = activity_data.get('watts')
            watt_numbers = watt_data.get('data')

            # Calculation of CHO consumption
            logging.info("Calculating CHO consumption...")

            # Reset CHO count
            total_cho = calc_cho(watt_numbers)

            # Calculate fat consumption
            logging.info("Calculating fat consumption...")

            total_fat = calculate_fat(watt_numbers)

            # List of all CHO values calculated
            #cho_values = []

            # for power in watt_numbers:
            #     # Reset power
            #     current_power = 0

            #     # Extract the current power value
            #     current_power = power

            #     # validate the power information
            #     if current_power is not None:

            #         # if the power value is below the threshold value apply the first formula
            #         if current_power <= CURVE_THRESHOLD:

            #             # call function with linear function 1
            #             total_cho = total_cho + calculate_cho(F1_SLOPE,
            #                                                 F1_INTERCEPT,
            #                                                 current_power,
            #                                                 cho_values)

            #             # Since the power value is above the threshold use the second formula
            #         else:

            #             # call function with linear function 2
            #             total_cho = total_cho + calculate_cho(F2_SLOPE,
            #                                                 F2_INTERCEPT,
            #                                                 current_power,
            #                                                 cho_values)

            # Inform user about the results
            logging.info("CHO calculation finished. Updating strava activity...")

            # Update description of Strava activity
            body = {'description': 'Total carbohydrates burned (g): '
                        + str(round(total_cho))
                        + ' kcal: '
                        + str(round(total_cho*4.184))
                        + '\nCarbohydrates burned per hour (g): '
                        + str(round(total_cho / activity_duration * 60 * 60))
                        + '\nTotal fat burned (g): '
                        + str(round(total_fat))
                        + ' kcal: '
                        + str(round(total_fat*9))
                        + '\nFat burned per hour (g): '
                        + str(round(total_fat / activity_duration * 60 * 60))}

            response = requests.put(BASE_URL+activity_id,
                                params={'access_token': access_token},
                                data=body)
            if response.status_code != requests.codes.ok: #pylint: disable=no-member
                response.raise_for_status()

            # Inform user about the results
            logging.info("Strava activity updated. Processing has finished.")
        else:
            response.raise_for_status()

    else:
        logging.info("Unsupported activity type. Processing terminated")
