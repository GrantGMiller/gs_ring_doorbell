from urllib.request import Request, urlopen
import requests

# url = 'https://api.ring.com/clients_api/ring_devices?api_version=9&auth_token=U5ozQinKYnFTNU4Rm79y'

url = 'http://192.168.68.113/clients_api/ring_devices?api_version=9&auth_token=U5ozQinKYnFTNU4Rm79y'

# resp = requests.get(url)
# if resp.status_code != 200:
#     raise Exception('bummer')

req = Request(url)
req.add_header('Accept', '*/*')
req.add_header('Accept-Encoding', 'gzip, deflate')
req.add_header('Connection', 'keep-alive')

resp = urlopen(req)
print(resp.read())