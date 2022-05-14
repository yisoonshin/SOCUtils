"""Collection of functions to help determine if a domain is parked"""
import requests

parking_references = [
    'parked',
    'parking',
    'courtesy of',
    'registered'
]


def request_based_check(domain):
    """Runs through series of heuristics suggesting that domain is parked."""
    checks = {
        'parent_domain_unreachable': False,
        'contains_parking_references': False,
        'nonexistent_uri_reachable': False
    }

    try:
        r1 = requests.get('http://{}'.format(domain))
        text = r1.text
        # search for the common verbiage seen in parking pages
        if any(ref in text for ref in parking_references):
            checks['contains_parking_references'] = True

        # if a request to a nonexistent page doesn't return 400
        # and is the same as the homepage, then it's likely a parked domain
        r2 = requests.get('http://{}/nonexistentpage.html'.format(domain))
        if r2.status_code < 400 and r2.text == r1.text:
            checks['nonexistent_uri_reachable'] = True

    except ConnectionError:
        # if there is no DNS record, it's probable that it's parked
        checks['parent_domain_unreachable'] = True

    return checks


def is_parked(checks):
    """Simple algo based on result of request_based_check"""
    
    if checks['parent_domain_unreachable']:
        return True
    else:
        if checks['contains_parking_references'] and checks['nonexistent_uri_reachable']:
            return True
    return False
