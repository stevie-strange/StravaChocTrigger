"""main file for the queue trigger""" #pylint: disable=invalid-name,C0305
import logging
import math
import os
import time

import requests
import azure.functions as func
import numpy as np
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from requests.models import Response

########## CONSTANTS ####################
# Base Strava URL for activities
BASE_URL = 'https://www.strava.com/api/v3/activities/'



def calc_cho(power):
    """function to calculate CHO consumption based on e function"""

    # Convert to numpy array and filter out None values
    power_array = np.array([p for p in power if p is not None], dtype=float)

    if len(power_array) == 0:
        return 0

    # Calculate CHO consumption in grams per hour using vectorized operations
    cho_per_hour = (24.4817243 - 0.358447879 * power_array +
                    0.00708969851 * power_array**2 -
                    0.00000982862627 * power_array**3)

    # Scale result down to recording interval of 1s
    cho_per_second = cho_per_hour / 3600

    # Sum total consumption
    return np.sum(cho_per_second)


# Calculate fat consumption based on the power
def calculate_fat(power):
    """function to calculate the fat consumption"""

    # Convert to numpy array and filter out None and zero/negative values
    power_array = np.array([p for p in power if p is not None and p > 0], dtype=float)

    if len(power_array) == 0:
        return 0

    # Calculate fat consumption in grams per hour using vectorized operations
    fat_per_hour = (9.92211011 + 0.20866082 * power_array -
                    0.0000796973456 * power_array**2 -
                    0.00000305255098 * power_array**3)

    # Scale result down to recording interval of 1s
    fat_per_second = fat_per_hour / 3600

    # Sum total consumption
    return np.sum(fat_per_second)


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
            data={
                'client_id': os.getenv('StravaClientID'),
                'client_secret': os.getenv('StravaClientSecret'),
                'refresh_token': client.get_secret("StravaRefreshToken").value,
                'grant_type': 'refresh_token'
            },
            timeout=(3, 10)  # (connect timeout, read timeout)
        )

        # proceed if request was successfull
        if response.status_code == 200:

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


def _fetch_json(url, params=None, timeout=(3, 10)):
    """Helper to GET a URL, raise on non-200 and return parsed JSON.

    Centralises requests.get + status handling to reduce duplication and
    make the logic easier to test.
    """
    response = requests.get(url, params=params, timeout=timeout)
    if response.status_code != 200:
        response.raise_for_status()
    return response.json()


def build_description(total_cho: float, total_fat: float, activity_duration: float) -> str:
    """Build the Strava activity description text.

    This is a pure, unit-testable helper that formats the calculated
    nutrition metrics into the string uploaded to Strava.

    It defensively handles invalid activity_duration (<=0, NaN, inf) by
    returning 'n/a' for per-hour fields to avoid ZeroDivisionError.
    """
    # Normalize numeric inputs
    try:
        cho_rounded = round(float(total_cho))
    except (TypeError, ValueError):
        cho_rounded = 'n/a'

    try:
        fat_rounded = round(float(total_fat))
    except (TypeError, ValueError):
        fat_rounded = 'n/a'

    # Check duration validity
    per_hour_cho = 'n/a'
    per_hour_fat = 'n/a'
    try:
        dur = float(activity_duration)
        if dur > 0 and math.isfinite(dur):
            per_hour_cho = str(round(total_cho / dur * 60 * 60))
            per_hour_fat = str(round(total_fat / dur * 60 * 60))
    except (TypeError, ValueError):
        # leave as 'n/a'
        pass

    cho_kcal = 'n/a' if cho_rounded == 'n/a' else str(round(total_cho * 4.184))
    fat_kcal = 'n/a' if fat_rounded == 'n/a' else str(round(total_fat * 9))

    return (
        'Total carbohydrates burned (g): '
        + str(cho_rounded)
        + ' kcal: '
        + cho_kcal
        + '\nCarbohydrates burned per hour (g): '
        + per_hour_cho
        + '\nTotal fat burned (g): '
        + str(fat_rounded)
        + ' kcal: '
        + fat_kcal
        + '\nFat burned per hour (g): '
        + per_hour_fat
    )


def main(msg: func.QueueMessage) -> None:
    """Main function"""

    logging.info('Python queue trigger function processed a queue item: %s',
                 msg.get_body().decode('utf-8'))

    # Get access token
    access_token = get_access_token()

    logging.info('Reading activity data...')

    activity_id = msg.get_body().decode('utf-8')
    # Load activity metadata
    data = _fetch_json(BASE_URL + activity_id,
                       params={'access_token': access_token},
                       timeout=(3, 10))

    # Only process defined activity types
    if data.get('type') in ('Ride', 'VirtualRide'):

        # Get activity duration
        activity_duration = data.get('elapsed_time')

        logging.info("Load power data of activity...")
        # Get power data stream for 1 activity based on time domain
        payload = {
            'access_token': access_token,
            'keys': 'watts',
            'key_by_type': 'true',
            'series_type': 'time',
        }
        activity_data = _fetch_json(
            BASE_URL + activity_id + '/streams', params=payload, timeout=(3, 10)
        )

        # Data processing - Reading the watt stream
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

        # List of all CHO values calculated (legacy linear-method commented out)
        # Inform user about the results
        logging.info("CHO calculation finished. Updating strava activity...")

        # Update description of Strava activity
        body = {'description': build_description(total_cho, total_fat, activity_duration)}

        response = requests.put(
            BASE_URL + activity_id,
            params={'access_token': access_token},
            data=body,
            timeout=(3, 10),
        )

        if response.status_code != 200:
            response.raise_for_status()

        # Inform user about the results
        logging.info("Strava activity updated. Processing has finished.")


    else:
        logging.info("Unsupported activity type. Processing terminated")

