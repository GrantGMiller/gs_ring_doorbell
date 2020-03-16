import requests
import creds


class RingOauth:
    """RingOauth class constants"""
    ENDPOINT = 'https://oauth.ring.com/oauth/token'
    CLIENT_ID = 'ring_official_android'
    SCOPE = ['client']
    HEADERS = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9.0;'
                      'SM-G850F Build/LRX22G)'
    }

    def __init__(self, username, password):
        self._username = username
        self._password = password
        self._token = None

    def GetToken(self):
        if self._token is None:
            return self.GetNewToken():

    def GetNewToken():
        pass


def FetchToken():
    sesh = requests.session()
    resp = sesh.get(RingOauth.ENDPOINT)
    print('resp.text=\r\n', resp.text)


FetchToken()
