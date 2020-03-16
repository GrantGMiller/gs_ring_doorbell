# this is to test a new release of the original python repo
# https://github.com/tchellomello/python-ring-doorbell

from pprint import pprint
from ring_doorbell import Ring, Auth
import creds

auth = Auth()
auth.fetch_token(creds.username, creds.password)
ring = Ring(auth)

pprint(ring.devices)