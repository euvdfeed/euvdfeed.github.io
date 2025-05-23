# EUVD Feeds

EUVD feed by searching CVE data in fediverse instances.

inspiration: https://fedisecfeeds.github.io

## Run

Test mode (will only fetch limited data to save time of testing):

`export TESTMODE=1`

Get data and render:

`./index_data.py`

This will output fedi_cve_feed.json which you can use fetch directly via Github's API.

Only render:

`./renderer.py`

