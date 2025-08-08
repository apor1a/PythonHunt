def vt_ip_check(target):
    """
    Checks VirusTotal for known malicious actions/malware associated with the IP.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    headers = {"x-apikey": VT_API}
    response = requests.get(url, headers=headers)
    attributes = response.json().get("data", {}).get("attributes", {})
    last_analysis = attributes.get("last_analysis_stats", {})
    print(
        """
    VirusTotal
    ----------"""
    )
    if response.status_code == 200:
        print(
            """
    Scan Stats:
    Country is {}
    AS Owner is {}
    Harmless: {}
    Suspicious: {}
    Malicious: {}
    Undetected: {}
            """.format(
                attributes.get("country", "Not Found"),
                attributes.get("as_owner", "Not Found"),
                last_analysis.get("harmless", "None."),
                last_analysis.get("suspicious", "None."),
                last_analysis.get("malicious", "None."),
                last_analysis.get("undetected", "None."),
            )
        )
    else:
        print(
            """
    Error:
    VirusTotal Response Code {}""".format(
                response.status_code
            )
        )

def vt_domain_check(target):
    """
    Checks VirusTotal for known malicious actions/malware associated with the Domain.
    """
    url = f"https://www.virustotal.com/api/v3/domains/{target}"
    headers = {"x-apikey": VT_API}
    response = requests.get(url, headers=headers)
    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})
    rank = data.get("data", {}).get("attributes", {}).get("popularity_ranks", {})
    last_analysis = (
        data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    )
    creation_date = attributes.get("creation_date")
    print(
        """
    VirusTotal
    ----------"""
    )
    if response.status_code == 200:
        print(
            """
    Domain Created: {}
    Alexa Rank: {}
    Cisco Umbrella Rank: {}
    Overall Reputation: {}
    Harmless: {}
    Suspicious: {}
    Malicious: {}
    Undetected: {}
            """.format(
                datetime.fromtimestamp(creation_date).strftime("%Y-%m-%d %I:%M:%S")
                if creation_date
                else "None",
                rank.get("Alexa", {}).get("rank", "No Data."),
                rank.get("Cisco Umbrella", {}).get("rank", "No Data."),
                attributes.get("reputation", "No Data."),
                last_analysis.get("harmless", "None."),
                last_analysis.get("suspicious", "None."),
                last_analysis.get("malicious", "None."),
                last_analysis.get("undetected", "None."),
            )
        )
    else:
        print(
            """
    Error:
    VirusTotal Response Code {}""".format(
                response.status_code
            )
        )