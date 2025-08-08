
import os

import requests
def greynoise_ip(target):
    GREYNOISE_API = os.getenv("GREYNOISE_API")
    """
    Checking Greynoise for data on scanning IPs and "noisy" traffic.
    """
    url = f"https://api.greynoise.io/v3/community/{target}"
    headers = {
        'key': GREYNOISE_API
    }
    response = requests.request("GET", url, headers=headers)
    print(
        """
    Greynoise
    ----------"""
    )
    if response.status_code == 200:
        data = response.json()
        print(
            """
    IP: {}
    Noise: {}
    RIOT: {}
    Classification: {}
    Name: {}
    Last Seen: {}
    Link: {}
            """.format(
                data.get("ip", "No Data."),
                data.get("noise", "No Data."),
                data.get("riot", "No Data"),
                data.get("classification", "No Data."),
                data.get("name", "No Data."),
                data.get("last_seen", "No Data."),
                data.get("link", "No Data.")
            )
        )
    elif response.status_code == 404:
        print(
            """
    IP not found in Greynoise database.
            """
        )
    else:
        print(
            """
    Greynoise Response Code: {}
            """.format(
                response.status_code
            )
        )