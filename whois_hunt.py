import whois
import whoisdomain as whois

def whois_lookup(target):
    """
    Basic WHOIS data lookup. Uses https://github.com/DannyCork/python-whois/
    """
    try:
        domain = whois.query(target)
        if domain is None:
            print("Domain not found in WHOIS")
            name = "Not Found."
            created = "No Data."
            expires = "No Data."
            updated = "No Data."
            reg = "No Data."
            country = "No Data."
            nameservers = None
            ns_clean = None
        else:
            name = domain.name
            created = domain.creation_date
            expires = domain.expiration_date
            updated = domain.last_updated
            reg = domain.registrar
            country = domain.registrant_country
            nameservers = domain.name_servers
            ns_clean = set(server.strip() for server in nameservers)
    except AttributeError as error:
        print(error)
    else:
        print(
            """__________________________________________________

    Investigating Domain "{}"


    WHOIS
    ----------

    Created on {}
    Expires on {}
    Registrar: {}
    Last Updated: {}
    Registered in: {}
    Name Servers: {}
        """.format(
                name if name else "No Data",
                created if created else "No Data",
                expires if expires else "No Data",
                reg if reg else "No Data",
                updated if updated else "No Data",
                country if country else "No Data",
                ", ".join(sorted(list(ns_clean))) if ns_clean else "No Data",
            )
        )
