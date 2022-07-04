Usage: python .\ioc_parser.py [ioc file] [optional arguments]
Example: python .\vt_ioc_parser.py samdoge_iocs.txt
  - use full path T:\python_development\oss_utils\ioc_parser\vt_ioc_parser.py if running from outside this folder

optional arguments:

  -h, --help            show this help message and exit
  -p PASSIVE_DNS, --passive_dns PASSIVE_DNS
                        passive DNS records to test if IP is shared hosting
  -f FILES, --files FILES
                        pull in threat mapping for communicating files
  -c COMMENTS, --comments COMMENTS
                        pull in threat mapping for communicating files
  -a ABUSE, --abuseipdb    
                        ingest AbuseIPDB confidence scores

Will take in doc w/IPv4, domain, and hash IOCs and export XLSX of relevant datapoints for efficient triage.

**API keys are stored in config.json - treat with caution!!**