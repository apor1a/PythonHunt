import ipinfo
import pprint
import os
def fetch_ipinfo(target):
    access_token = os.getenv("IPINFO_API")
    handler = ipinfo.getHandler(access_token)
    details = handler.getDetails(target)
    print(details.city)
    pprint.pprint(details.all)