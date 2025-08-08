def geo_info(target):

    #Basic geolocation and IP ownership information.

    data = requests.get(f"https://ipinfo.io/{target}/json").json()
    print(
        """_________________________________________

    Investigating {}:

    Connecting from {}, {}; {}.
    IP belongs to {}.
        """.format(
            data.get("ip", "IP Not Found."),
            data.get("city", "Not Found."),
            data.get("region", "Not Found."),
            data.get("country", "Not Found."),
            data.get("org", "Not Found."),
        )
    )