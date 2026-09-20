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

# --- Substrate oxidation model -------------------------------------------
# Fitted to a spiroergometry test from August 2026 (see GitHub issue #26):
# 8 stages of ~30 s at 125..300 W in 25 W steps.
#
#   W    | 125   150   175   200   225   250   275   300
#   CHO  | 101.2 127.3 140.9 161.6 199.2 244.9 261.2 275.5  g/h
#   Fat  | 18.0  16.4  17.8  17.7  9.3   0.0   0.0   0.0    g/h
#   EE   | 595   689   759   845   924   1029  1097  1157   kcal/h
#   RER  | 0.92  0.93  0.94  0.94  0.97  1.03  1.05  1.12
#
# A synthetic 0 W resting anchor (24.48 g/h CHO, 9.92 g/h fat, the intercepts of
# the previous model) is included in both fits so coasting seconds behave as before.
#
# CHO: quadratic in power. CHO oxidation rises exponentially with relative
# intensity in principle (Brooks & Mercier 1994, J Appl Physiol 76:2253) but is
# close to linear over a graded test and curvilinear fits do not improve on it
# (Brun et al. 2026, Metabolites 16:121). The quadratic keeps the mild upward
# curvature without the exponential's runaway extrapolation. Because CHO
# oxidation cannot exceed total energy expenditure, the result is capped at
# 100 % CHO of the report's energy expenditure line (linear in power, R2 0.997),
# which also compensates the RER > 1 stages where indirect calorimetry
# over-reads CHO.
#
# Fat: third-order polynomial, the conventional form for fat oxidation
# kinetics (Achten & Jeukendrup; Cheneviere et al. 2009, MSSE 41:1615), fitted
# to the anchor and stages 1-6 and clamped at zero above Fatmin (~250 W).
#
# Coefficients are ordered high -> low for np.polyval.
CHO_POLY = np.array([1.399139593699e-03, 4.617486849396e-01, 2.324296033823e+01])
ENERGY_KCAL_PER_H_POLY = np.array([3.269952380952, 192.047619047619])
KCAL_PER_G_CHO = 4.184
FAT_POLY = np.array([-8.359199834721e-06, 2.387407584606e-03,
                     -1.139353733339e-01, 9.961256016061e+00])



def _clean_power(power):
    """Return the power stream as a float array without None/NaN, clipped at 0 W."""
    power_array = np.array(power, dtype=float)
    power_array = power_array[~np.isnan(power_array)]
    return np.clip(power_array, 0, None)


def calc_cho(power):
    """Total CHO consumption (g) for a 1 Hz power stream.

    Quadratic model in power, capped at 100 % CHO of the energy expenditure.
    See the substrate oxidation model notes in the constants section.
    """
    power_array = _clean_power(power)

    if len(power_array) == 0:
        return 0

    cho_per_hour = np.minimum(
        np.polyval(CHO_POLY, power_array),
        np.polyval(ENERGY_KCAL_PER_H_POLY, power_array) / KCAL_PER_G_CHO)

    # Scale result down to recording interval of 1s and sum total consumption
    return np.sum(cho_per_hour / 3600)


def calculate_fat(power):
    """Total fat consumption (g) for a 1 Hz power stream.

    Cubic model in power, clamped at zero above Fatmin.
    See the substrate oxidation model notes in the constants section.
    """
    power_array = _clean_power(power)

    if len(power_array) == 0:
        return 0

    fat_per_hour = np.clip(np.polyval(FAT_POLY, power_array), 0, None)

    # Scale result down to recording interval of 1s and sum total consumption
    return np.sum(fat_per_hour / 3600)


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

