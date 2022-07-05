
# SOCUtils
Many an analyst has experienced this - you're in a last-minute crunch to process a big chunk of data, and the internal debate is whether or not it's more efficient to spend time coming up with a script to automate the work. The goal of this repo is to provide tooling addressing scenarios that we've seen come up in our work and studies, so that you don't have to reinvent the wheel in the heat of the moment.

Feel free, however, to review these during your downtime to supplement your learning as well as contribute edits that you feel address edge cases or align code to best practices. We don't claim to be experts, but we're here to help others "git 'er done!".

## IOC Parser
Have you ever been handed a long list of IOCs of possibly varying quality, and needed a more efficient way to sift through the most important ones? This script will automate enumeration via VirusTotal and AbuseIPDB APIs (you must have your own keys) and output an Excel doc with the IOCs categorized by type and sorted by number of vendors flagging the IOC as malicious/suspicious. Functionality includes:
* Flagging whether IP addresses are used as shared hosting (often leads to false positives)
* Associating passive DNS records, communicating files, and community comments

## ParkingCheck
Some of our teammates perform subdomain fuzzing on a routine basis to see if threat actors are performing clones of our partners' sites. Their goal was to de-prioritize partner domains that were in a "parked" state since the threat would not be as immediate. This module aims to identify parked domains via request-based heuristics:
* If the domain can't be visited at all, indicating lack of a DNS A record (ConnectionError)
* If it can be reached, does the root page include references to parking, registration, etc.?
* If we try to visit a nonsensical URI, does it return the same content as the homepage as opposed to returning a 404 error?

## cryptoTools
No fully fleshed out encryption policy for team project files? You can try using the scripts in this module to generate a public key pair (RSA 4096 block) and AES128 cipher. The symmetric cipher is used for transforming the content for speed, and its details (.conf file) encrypted and decrypted using the RSA keys.
