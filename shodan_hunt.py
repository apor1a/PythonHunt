import shodan
import os
from dotenv import load_dotenv
def shodan_check(target):
    SHODAN_API = os.getenv("SHODAN_API")
    """
    Double check geo and org information with Shodan, as well as pull
    additional information on the host.
    """
    print(
        """
    Shodan
    ----------"""
    )
    try:
        data = shodan.Shodan(SHODAN_API).host(target)
    except shodan.APIError as error:
        print(f"    {error}")
    else:
        print(
            """
    Geolocation double-check:
        {}, {}, {}
        Owned by {}.""".format(
                data.get("city", "No Data."),
                data.get("country_name", "No Data"),
                data.get("region_code", "No Data."),
                data.get("org", "No Data."),
            )
        )
        print(
            """
    Additional Shodan Info:
        OS: {}
        Port(s): {}
        Hostname: {}
        Last Updated: {}
            """.format(
                data.get("os", "No Data."),
                data.get("ports", "No Data."),
                data.get("hostnames", "No Data."),
                data.get("last_update", "No Data"),
            )
        )
