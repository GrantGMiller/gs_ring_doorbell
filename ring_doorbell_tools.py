# coding: utf-8
# vim:sw=4:ts=4:et:
"""Python Ring Doorbell wrapper."""
import time
from collections import defaultdict

import pytz

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

import requests
from uuid import uuid4 as uuid
from extronlib.system import File, Wait
from extronlib import event
from datetime import datetime
import json

DEBUG = True
if DEBUG is False:
    print = lambda *a, **k: None


class Logger:
    def error(self, *a, **k):
        print('Logger.error:', a, k)


_LOGGER = Logger()

# coding: utf-8
# vim:sw=4:ts=4:et:
"""Constants."""
HEADERS = {
    'Content-Type': 'application/x-www-form-urlencoded; charset: UTF-8',
    'User-Agent': 'Dalvik/1.6.0 (Linux; Android 4.4.4; Build/KTU84Q)',
    'Accept-Encoding': 'gzip, deflate'
}

# number of attempts to refresh token
RETRY_TOKEN = 3

# default suffix for session cache file
CACHE_ATTRS = {'account': None, 'alerts': None, 'token': None}

CACHE_FILENAME = 'ring_doorbell-session.json'

# code when item was not found
NOT_FOUND = -1

# API endpoints
OAUTH_ENDPOINT = 'https://oauth.ring.com/oauth/token'
API_VERSION = '9'
API_URI = 'https://api.ring.com'
CHIMES_ENDPOINT = '/clients_api/chimes/{0}'
DEVICES_ENDPOINT = '/clients_api/ring_devices'
DINGS_ENDPOINT = '/clients_api/dings/active'
DOORBELLS_ENDPOINT = '/clients_api/doorbots/{0}'
PERSIST_TOKEN_ENDPOINT = '/clients_api/device'

HEALTH_DOORBELL_ENDPOINT = DOORBELLS_ENDPOINT + '/health'
HEALTH_CHIMES_ENDPOINT = CHIMES_ENDPOINT + '/health'
LIGHTS_ENDPOINT = DOORBELLS_ENDPOINT + '/floodlight_light_{1}'
LINKED_CHIMES_ENDPOINT = CHIMES_ENDPOINT + '/linked_doorbots'
LIVE_STREAMING_ENDPOINT = DOORBELLS_ENDPOINT + '/vod'
NEW_SESSION_ENDPOINT = '/clients_api/session'
RINGTONES_ENDPOINT = '/ringtones'
SIREN_ENDPOINT = DOORBELLS_ENDPOINT + '/siren_{1}'
SNAPSHOT_ENDPOINT = "/clients_api/snapshots/image/{0}"
SNAPSHOT_TIMESTAMP_ENDPOINT = "/clients_api/snapshots/timestamps"
TESTSOUND_CHIME_ENDPOINT = CHIMES_ENDPOINT + '/play_sound'
URL_DOORBELL_HISTORY = DOORBELLS_ENDPOINT + '/history'
URL_RECORDING = '/clients_api/dings/{0}/recording'

# chime test sound kinds
KIND_DING = 'ding'
KIND_MOTION = 'motion'
CHIME_TEST_SOUND_KINDS = (KIND_DING, KIND_MOTION)

# default values
CHIME_VOL_MIN = 0
CHIME_VOL_MAX = 10

DOORBELL_VOL_MIN = 0
DOORBELL_VOL_MAX = 11

DOORBELL_EXISTING_TYPE = {
    0: 'Mechanical',
    1: 'Digital',
    2: 'Not Present'}

SIREN_DURATION_MIN = 0
SIREN_DURATION_MAX = 120

# device model kinds
CHIME_KINDS = ['chime']
CHIME_PRO_KINDS = ['chime_pro']

DOORBELL_KINDS = ['doorbot', 'doorbell', 'doorbell_v3']
DOORBELL_2_KINDS = ['doorbell_v4', 'doorbell_v5']
DOORBELL_PRO_KINDS = ['lpd_v1', 'lpd_v2']
DOORBELL_ELITE_KINDS = ['jbox_v1']

FLOODLIGHT_CAM_KINDS = ['hp_cam_v1', 'floodlight_v2']
SPOTLIGHT_CAM_BATTERY_KINDS = ['stickup_cam_v4']
SPOTLIGHT_CAM_WIRED_KINDS = ['hp_cam_v2']
STICKUP_CAM_KINDS = ['stickup_cam', 'stickup_cam_v3']
STICKUP_CAM_BATTERY_KINDS = ['cocoa_camera', 'stickup_cam_lunar']
STICKUP_CAM_WIRED_KINDS = ['stickup_cam_elite']

# error strings
MSG_BOOLEAN_REQUIRED = "Boolean value is required."
MSG_EXISTING_TYPE = "Integer value where {0}.".format(DOORBELL_EXISTING_TYPE)
MSG_GENERIC_FAIL = 'Sorry.. Something went wrong...'
FILE_EXISTS = 'The file {0} already exists.'
MSG_VOL_OUTBOUND = 'Must be within the {0}-{1}.'
MSG_ALLOWED_VALUES = 'Only the following values are allowed: {0}.'

# structure acquired from reverse engineering to create auth token
OAUTH_DATA = {
    "client_id": "ring_official_android",
    "grant_type": "password",
    "scope": "client",
    "username": None,
    "password": None,
}

POST_DATA = {
    'api_version': API_VERSION,
    'device[hardware_id]': str(uuid()),
    'device[os]': 'android',
    'device[app_brand]': 'ring',
    'device[metadata][device_model]': 'KVM',
    'device[metadata][device_name]': 'Python',
    'device[metadata][resolution]': '600x800',
    'device[metadata][app_version]': '1.3.806',
    'device[metadata][app_instalation_date]': '',
    'device[metadata][manufacturer]': 'Qemu',
    'device[metadata][device_type]': 'desktop',
    'device[metadata][architecture]': 'desktop',
    'device[metadata][language]': 'en'}

PERSIST_TOKEN_DATA = {
    'api_version': API_VERSION,
    'device[metadata][device_model]': 'KVM',
    'device[metadata][device_name]': 'Python',
    'device[metadata][resolution]': '600x800',
    'device[metadata][app_version]': '1.3.806',
    'device[metadata][app_instalation_date]': '',
    'device[metadata][manufacturer]': 'Qemu',
    'device[metadata][device_type]': 'desktop',
    'device[metadata][architecture]': 'x86',
    'device[metadata][language]': 'en'}


# pylint: disable=useless-object-inheritance
class Ring(object):
    """A Python Abstraction object to Ring Door Bell."""

    def __init__(self, username, password, debug=False, persist_token=False,
                 push_token_notify_url="http://localhost/", reuse_session=True,
                 cache_file=CACHE_FILENAME):
        """Initialize the Ring object."""
        print('Initialize the Ring object.')
        self.is_connected = None
        self.token = None
        self.params = None
        self._persist_token = persist_token
        self._push_token_notify_url = push_token_notify_url

        self.debug = debug
        self.username = username
        self.password = password
        self.session = requests.Session()

        self.cache = CACHE_ATTRS
        self.cache['account'] = self.username
        self.cache_file = cache_file
        self._reuse_session = reuse_session

        self._knownEvents = defaultdict(dict)
        #   int(ID): dict(eventDetails)
        #   }

        utc = pytz.utc
        nowDT = datetime.utcnow()
        self._scriptStartDT = datetime(
            nowDT.year, nowDT.month, nowDT.day,
            nowDT.hour, nowDT.minute, nowDT.second,
            tzinfo=utc)  # ignore events that happen before this DT
        self._motionEventCallback = None
        self._dingEventCallback = None
        self._connectedCallback = None
        self._disconnectedCallback = None
        self._otherEventCallback = None

        self._wait_Update = Wait(60, self._Update)

        self._maxLen = 15

        # tries to re-use old session
        if self._reuse_session:
            self.cache['token'] = self.token
            self._process_cached_session()
        else:
            self._authenticate()

        self._Update()  # force update on boot up

    @property
    def Motion(self):
        return self._motionEventCallback

    @Motion.setter
    def Motion(self, callback):
        # callback should accept two params, str(deviceName), dict(eventDetails)
        self._motionEventCallback = callback

    @property
    def Ding(self):
        return self._dingEventCallback

    @Ding.setter
    def Ding(self, callback):
        # callback should accept two params, str(deviceName), dict(eventDetails)
        self._dingEventCallback = callback

    @property
    def Other(self):
        return self._otherEventCallback

    @Other.setter
    def Other(self, callback):
        # callback should accept two params, str(deviceName), dict(eventDetails)
        self._otherEventCallback = callback

    @property
    def Connected(self):
        return self._connectedCallback

    @Connected.setter
    def Connected(self, callback):
        # callback should accept two params, self, str('Connected')
        self._connectedCallback = callback
        if self.is_connected:
            self._connectedCallback(self, 'Connected')

    @property
    def Disconnected(self):
        return self._disconnectedCallback

    @Disconnected.setter
    def Disconnected(self, callback):
        # callback should accept two params, self, str('Disconnected')
        self._disconnectedCallback = callback
        if not self.is_connected:
            self._disconnectedCallback(self, 'Disconnected')

    def _Update(self):
        print('_Update')

        self._maxLen = 0

        for devType, devList in self.devices.items():
            for device in devList:
                self._maxLen += 15
                for event in device.history(limit=15):
                    ID = event['id']
                    dt = event['created_at']
                    if dt < self._scriptStartDT:
                        # ignore events that happened before this script was started
                        continue

                    if ID not in self._knownEvents:
                        # this is a new event, trigger a callback
                        if event['kind'] == 'ding':
                            if self._disconnectedCallback:
                                self._dingEventCallback(device.name, dict(event))
                        elif event['kind'] == 'motion':
                            if self._motionEventCallback:
                                self._motionEventCallback(device.name, dict(event))
                        else:
                            if self._otherEventCallback:
                                self._otherEventCallback(device.name, dict(event))

                    # save the event into memory
                    self._knownEvents[ID] = dict(event)

        if len(self._knownEvents) > self._maxLen:
            self._ClearOldEvents()

        self._wait_Update.Restart()

    def _ClearOldEvents(self):
        # prevent memory leak from storing too many events in memory
        # if every device returned 15 events, then this would be the max len
        # we dont need to hold any more events than this
        while len(self._knownEvents) > self._maxLen:
            oldestEvent = None
            for _, evt in self._knownEvents.items():
                if oldestEvent is None:
                    oldestEvent = evt
                else:
                    if evt['created_at'] < oldestEvent['created_at']:
                        oldestEvent = evt

            removed = self._knownEvents.pop(oldestEvent['id'])
            print('removed=', removed)

    def _process_cached_session(self):
        """Process cache_file to reuse token instead."""
        if _exists_cache(self.cache_file):
            self.cache = _read_cache(self.cache_file)

            # if self.cache['token'] is None, the cache file was corrupted.
            # of if self.cache['account'] does not match with self.username
            # In both cases, a new auth token is required.
            if (self.cache['token'] is None) or \
                    (self.cache['account'] is None) or \
                    (self.cache['account'] != self.username):
                self._authenticate()
            else:
                # we need to set the self.token and self.params
                # to make use of the self.query() method
                self.token = self.cache['token']
                self.params = {'api_version': API_VERSION,
                               'auth_token': self.token}

                # test if token from cache_file is still valid and functional
                # if not, it should continue to get a new auth token
                url = API_URI + DEVICES_ENDPOINT
                req = self.query(url, raw=True)
                if req and req.status_code == 200:
                    self._authenticate(session=req)
                else:
                    self._authenticate()
        else:
            # first time executing, so we have to create a cache file
            self._authenticate()

    def _get_oauth_token(self):
        """Return Oauth Bearer token."""
        oauth_data = OAUTH_DATA.copy()
        oauth_data['username'] = self.username
        oauth_data['password'] = self.password

        response = self.session.post(OAUTH_ENDPOINT,
                                     data=oauth_data,
                                     headers=HEADERS)
        oauth_token = None
        if response.status_code == 200:
            oauth_token = response.json().get('access_token')
        return oauth_token

    def _authenticate(self, attempts=RETRY_TOKEN, session=None):
        """Authenticate user against Ring API."""
        url = API_URI + NEW_SESSION_ENDPOINT
        loop = 0
        while loop <= attempts:
            HEADERS['Authorization'] = \
                'Bearer {}'.format(self._get_oauth_token())
            loop += 1
            try:
                if session is None:
                    req = self.session.post((url),
                                            data=POST_DATA,
                                            headers=HEADERS)
                else:
                    req = session
            except requests.exceptions.RequestException as err_msg:
                _LOGGER.error("Error!! %s", err_msg)
                raise

            if not req:
                continue

            # if token is expired, refresh credentials and try again
            if req.status_code == 200 or req.status_code == 201:

                # the only way to get a JSON with token is via POST,
                # so we need a special conditional for 201 code
                if req.status_code == 201:
                    data = req.json().get('profile')
                    self.token = data.get('authentication_token')

                self._NewConnectionStatus(True)
                self.params = {'api_version': API_VERSION,
                               'auth_token': self.token}

                if self._persist_token and self._push_token_notify_url:
                    url = API_URI + PERSIST_TOKEN_ENDPOINT
                    PERSIST_TOKEN_DATA['auth_token'] = self.token
                    PERSIST_TOKEN_DATA['device[push_notification_token]'] = \
                        self._push_token_notify_url
                    req = self.session.put((url), headers=HEADERS,
                                           data=PERSIST_TOKEN_DATA)

                # update token if reuse_session is True
                if self._reuse_session:
                    self.cache['account'] = self.username
                    self.cache['token'] = self.token
                    _save_cache(self.cache, self.cache_file)

                return True

        self._NewConnectionStatus(False)
        req.raise_for_status()
        return True

    def _NewConnectionStatus(self, newState):
        print('_NewConnectionStatus(', newState)
        print('is_connected=', self.is_connected)
        if newState != self.is_connected:
            if newState is True:
                if self._connectedCallback:
                    self._connectedCallback(self, 'Connected')
            elif newState is False:
                if self._disconnectedCallback:
                    self._disconnectedCallback(self, 'Disconnected')

        self.is_connected = newState

    def query(self,
              url,
              attempts=RETRY_TOKEN,
              method='GET',
              raw=False,
              extra_params=None,
              json=None):
        """Query data from Ring API."""
        if self.debug:
            _LOGGER.debug("Querying %s", url)

        if self.debug and not self.is_connected:
            _LOGGER.debug("Not connected. Refreshing token...")
            self._authenticate()

        response = None
        loop = 0
        while loop <= attempts:
            if self.debug:
                _LOGGER.debug("running query loop %s", loop)

            # allow to override params when necessary
            # and update self.params globally for the next connection
            if extra_params:
                params = self.params
                params.update(extra_params)
            else:
                params = self.params

            loop += 1
            try:
                if method == 'GET':
                    req = self.session.get((url), params=urlencode(params))
                elif method == 'PUT':
                    req = self.session.put((url), params=urlencode(params))
                elif method == 'POST':
                    req = self.session.post(
                        (url), params=urlencode(params), json=json)

                if self.debug:
                    _LOGGER.debug("_query %s ret %s", loop, req.status_code)

            except requests.exceptions.RequestException as err_msg:
                _LOGGER.error("Error!! %s", err_msg)
                raise

            # if token is expired, refresh credentials and try again
            if req.status_code == 401:
                self._NewConnectionStatus(False)
                self._authenticate()
                continue

            if req.status_code == 200 or req.status_code == 204:
                # if raw, return session object otherwise return JSON
                if raw:
                    response = req
                else:
                    if method == 'GET':
                        response = req.json()
                break

        if self.debug and response is None:
            _LOGGER.debug("%s", MSG_GENERIC_FAIL)
        return response

    @property
    def devices(self):
        """Return all devices."""
        devs = {}
        devs['chimes'] = self.chimes
        devs['stickup_cams'] = self.stickup_cams
        devs['doorbells'] = self.doorbells
        return devs

    def __devices(self, device_type):
        """Private method to query devices."""
        lst = []
        url = API_URI + DEVICES_ENDPOINT
        try:
            if device_type == 'stickup_cams':
                req = self.query(url).get('stickup_cams')
                for member in list((obj['description'] for obj in req)):
                    lst.append(RingStickUpCam(self, member))

            if device_type == 'chimes':
                req = self.query(url).get('chimes')
                for member in list((obj['description'] for obj in req)):
                    lst.append(RingChime(self, member))

            if device_type == 'doorbells':
                req = self.query(url).get('doorbots')
                for member in list((obj['description'] for obj in req)):
                    lst.append(RingDoorBell(self, member))

                # get shared doorbells, however device is read-only
                req = self.query(url).get('authorized_doorbots')
                for member in list((obj['description'] for obj in req)):
                    lst.append(RingDoorBell(self, member, shared=True))

        except AttributeError:
            pass
        return lst

    @property
    def chimes(self):
        """Return a list of RingDoorChime objects."""
        return self.__devices('chimes')

    @property
    def stickup_cams(self):
        """Return a list of RingStickUpCam objects."""
        return self.__devices('stickup_cams')

    @property
    def doorbells(self):
        """Return a list of RingDoorBell objects."""
        return self.__devices('doorbells')

    def update(self):
        """Refreshes attributes for all linked devices."""
        for device_lst in self.devices.values():
            for device in device_lst:
                if hasattr(device, "update"):
                    _LOGGER.debug("Updating attributes from %s", device.name)
                    getattr(device, "update")
        return True


class RingGeneric(object):
    """Generic Implementation for Ring Chime/Doorbell."""

    def __init__(self, ring, name, shared=False):
        """Initialize Ring Generic."""
        self._ring = ring
        self.debug = self._ring.debug
        self.name = name
        self.shared = shared
        self._attrs = None
        self._health_attrs = None

        # alerts notifications
        self.alert_expires_at = None

        # force update
        self.update()

    def __repr__(self):
        """Return __repr__."""
        return "<{0}: {1}>".format(self.__class__.__name__, self.name)

    @property
    def family(self):
        """Return Ring device family type."""
        return None

    @property
    def model(self):
        """Return Ring device model name."""
        return None

    def has_capability(self, capability):
        """Return if device has specific capability."""
        return False

    def update(self):
        """Refresh attributes."""
        self._get_attrs()
        self._get_health_attrs()
        self._update_alert()

    @property
    def alert(self):
        """Return alert attribute."""
        return self._ring.cache['alerts']

    @alert.setter
    def alert(self, value):
        """Set attribute to alert."""
        self._ring.cache['alerts'] = value
        _save_cache(self._ring.cache, self._ring.cache_file)
        return True

    def _update_alert(self):
        """Verify if alert received is still valid."""
        # alert is no longer valid
        if self.alert and self.alert_expires_at:
            if datetime.now() >= self.alert_expires_at:
                self.alert = None
                self.alert_expires_at = None
                _save_cache(self._ring.cache, self._ring.cache_file)

    def _get_attrs(self):
        """Return attributes."""
        url = API_URI + DEVICES_ENDPOINT
        try:
            if self.family == 'doorbots' and self.shared:
                lst = self._ring.query(url).get('authorized_doorbots')
            else:
                lst = self._ring.query(url).get(self.family)
            index = _locator(lst, 'description', self.name)
            if index == NOT_FOUND:
                return None
        except AttributeError:
            return None

        self._attrs = lst[index]
        return True

    def _get_health_attrs(self):
        """Return health attributes."""
        if self.family == 'doorbots' or self.family == 'stickup_cams':
            url = API_URI + HEALTH_DOORBELL_ENDPOINT.format(self.account_id)
        elif self.family == 'chimes':
            url = API_URI + HEALTH_CHIMES_ENDPOINT.format(self.account_id)
        self._health_attrs = self._ring.query(url).get('device_health')

    @property
    def account_id(self):
        """Return account ID."""
        return self._attrs.get('id')

    @property
    def address(self):
        """Return address."""
        return self._attrs.get('address')

    @property
    def firmware(self):
        """Return firmware."""
        return self._attrs.get('firmware_version')

    # pylint: disable=invalid-name
    @property
    def id(self):
        """Return ID."""
        return self._attrs.get('device_id')

    @property
    def latitude(self):
        """Return latitude attr."""
        return self._attrs.get('latitude')

    @property
    def longitude(self):
        """Return longitude attr."""
        return self._attrs.get('longitude')

    @property
    def kind(self):
        """Return kind attr."""
        return self._attrs.get('kind')

    @property
    def timezone(self):
        """Return timezone."""
        return self._attrs.get('time_zone')

    @property
    def wifi_name(self):
        """Return wifi ESSID name."""
        return self._health_attrs.get('wifi_name')

    @property
    def wifi_signal_strength(self):
        """Return wifi RSSI."""
        return self._health_attrs.get('latest_signal_strength')

    @property
    def wifi_signal_category(self):
        """Return wifi signal category."""
        return self._health_attrs.get('latest_signal_category')


class RingDoorBell(RingGeneric):
    """Implementation for Ring Doorbell."""

    @property
    def family(self):
        """Return Ring device family type."""
        return 'doorbots'

    @property
    def model(self):
        """Return Ring device model name."""
        if self.kind in DOORBELL_KINDS:
            return 'Doorbell'
        elif self.kind in DOORBELL_2_KINDS:
            return 'Doorbell 2'
        elif self.kind in DOORBELL_PRO_KINDS:
            return 'Doorbell Pro'
        elif self.kind in DOORBELL_ELITE_KINDS:
            return 'Doorbell Elite'
        return None

    def has_capability(self, capability):
        """Return if device has specific capability."""
        if capability == 'battery':
            return self.kind in (DOORBELL_KINDS +
                                 DOORBELL_2_KINDS)
        elif capability == 'volume':
            return True
        return False

    @property
    def battery_life(self):
        """Return battery life."""
        value = 0
        if 'battery_life_2' in self._attrs:
            # Camera has two battery bays
            if self._attrs.get('battery_life') is not None:
                # Bay 1
                value += int(self._attrs.get('battery_life'))
            if self._attrs.get('battery_life_2') is not None:
                # Bay 2
                value += int(self._attrs.get('battery_life_2'))
            return value
        # Camera has a single battery bay
        # Latest stickup cam can be externally powered
        if self._attrs.get('battery_life') is not None:
            value = int(self._attrs.get('battery_life'))
            if value and value > 100:
                value = 100
        return value

    def check_alerts(self):
        """Return JSON when motion or ring is detected."""
        url = API_URI + DINGS_ENDPOINT
        self.update()

        try:
            resp = self._ring.query(url)[0]
        except (IndexError, TypeError):
            return None

        if resp:
            timestamp = resp.get('now') + resp.get('expires_in')
            self.alert = resp
            self.alert_expires_at = datetime.fromtimestamp(timestamp)

            # save to a pickle data
            if self.alert:
                _save_cache(self._ring.cache, self._ring.cache_file)
            return True
        return None

    @property
    def existing_doorbell_type(self):
        """
        Return existing doorbell type.

        0: Mechanical
        1: Digital
        2: Not Present
        """
        try:
            return DOORBELL_EXISTING_TYPE[
                self._attrs.get('settings').get('chime_settings').get('type')]
        except AttributeError:
            return None

    @existing_doorbell_type.setter
    def existing_doorbell_type(self, value):
        """
        Return existing doorbell type.

        0: Mechanical
        1: Digital
        2: Not Present
        """
        if value not in DOORBELL_EXISTING_TYPE.keys():
            _LOGGER.error("%s", MSG_EXISTING_TYPE)
            return False
        params = {
            'doorbot[description]': self.name,
            'doorbot[settings][chime_settings][type]': value}
        if self.existing_doorbell_type:
            url = API_URI + DOORBELLS_ENDPOINT.format(self.account_id)
            self._ring.query(url, extra_params=params, method='PUT')
            self.update()
            return True
        return None

    @property
    def existing_doorbell_type_enabled(self):
        """Return if existing doorbell type is enabled."""
        if self.existing_doorbell_type:
            if self.existing_doorbell_type == DOORBELL_EXISTING_TYPE[2]:
                return None
            return \
                self._attrs.get('settings').get('chime_settings').get('enable')
        return False

    @existing_doorbell_type_enabled.setter
    def existing_doorbell_type_enabled(self, value):
        """Enable/disable the existing doorbell if Digital/Mechanical."""
        if self.existing_doorbell_type:

            if not isinstance(value, bool):
                _LOGGER.error("%s", MSG_BOOLEAN_REQUIRED)
                return None

            if self.existing_doorbell_type == DOORBELL_EXISTING_TYPE[2]:
                return None

            params = {
                'doorbot[description]': self.name,
                'doorbot[settings][chime_settings][enable]': value}
            url = API_URI + DOORBELLS_ENDPOINT.format(self.account_id)
            self._ring.query(url, extra_params=params, method='PUT')
            self.update()
            return True
        return False

    @property
    def existing_doorbell_type_duration(self):
        """Return duration for Digital chime."""
        if self.existing_doorbell_type:
            if self.existing_doorbell_type == DOORBELL_EXISTING_TYPE[1]:
                return self._attrs.get('settings'). \
                    get('chime_settings').get('duration')
        return None

    @existing_doorbell_type_duration.setter
    def existing_doorbell_type_duration(self, value):
        """Set duration for Digital chime."""
        if self.existing_doorbell_type:

            if not ((isinstance(value, int)) and
                    (DOORBELL_VOL_MIN <= value <= DOORBELL_VOL_MAX)):
                _LOGGER.error("%s", MSG_VOL_OUTBOUND.format(DOORBELL_VOL_MIN,
                                                            DOORBELL_VOL_MAX))
                return False

            if self.existing_doorbell_type == DOORBELL_EXISTING_TYPE[1]:
                params = {
                    'doorbot[description]': self.name,
                    'doorbot[settings][chime_settings][duration]': value}
                url = API_URI + DOORBELLS_ENDPOINT.format(self.account_id)
                self._ring.query(url, extra_params=params, method='PUT')
                self.update()
                return True
        return None

    def history(self, limit=30, timezone=None, kind=None,
                enforce_limit=False, older_than=None, retry=8):
        """
        Return history with datetime objects.

        :param limit: specify number of objects to be returned
        :param timezone: determine which timezone to convert data objects
        :param kind: filter by kind (ding, motion, on_demand)
        :param enforce_limit: when True, this will enforce the limit and kind
        :param older_than: return older objects than the passed event_id
        :param retry: determine the max number of attempts to archive the limit
        """
        queries = 0
        original_limit = limit

        # set cap for max queries
        if retry > 10:
            retry = 10

        while True:
            params = {'limit': str(limit)}
            if older_than:
                params['older_than'] = older_than

            url = API_URI + URL_DOORBELL_HISTORY.format(self.account_id)
            response = self._ring.query(url, extra_params=params)

            # cherrypick only the selected kind events
            if kind:
                response = list(filter(
                    lambda array: array['kind'] == kind, response))

            # convert for specific timezone
            utc = pytz.utc
            if timezone:
                mytz = pytz.timezone(timezone)

            for entry in response:
                dt_at = datetime.strptime(entry['created_at'],
                                          '%Y-%m-%dT%H:%M:%S.000Z')
                utc_dt = datetime(dt_at.year, dt_at.month, dt_at.day,
                                  dt_at.hour, dt_at.minute, dt_at.second,
                                  tzinfo=utc)
                if timezone:
                    tz_dt = utc_dt.astimezone(mytz)
                    entry['created_at'] = tz_dt
                else:
                    entry['created_at'] = utc_dt

            if enforce_limit:
                # return because already matched the number
                # of events by kind
                if len(response) >= original_limit:
                    return response[:original_limit]

                # ensure the loop will exit after max queries
                queries += 1
                if queries == retry:
                    _LOGGER.debug("Could not find total of %s of kind %s",
                                  original_limit, kind)
                    break

                # ensure the kind objects returned to match limit
                limit = limit * 2

            else:
                break

        return response

    @property
    def last_recording_id(self):
        """Return the last recording ID."""
        try:
            return self.history(limit=1)[0]['id']
        except (IndexError, TypeError):
            return None

    @property
    def live_streaming_json(self):
        """Return JSON for live streaming."""
        url = API_URI + LIVE_STREAMING_ENDPOINT.format(self.account_id)
        req = self._ring.query((url), method='POST', raw=True)
        if req and req.status_code == 204:
            url = API_URI + DINGS_ENDPOINT
            try:
                return self._ring.query(url)[0]
            except (IndexError, TypeError):
                pass
        return None

    def recording_download(self, recording_id, filename=None, override=False):
        """Save a recording in MP4 format to a file or return raw."""
        if not self.has_subscription:
            msg = "Your Ring account does not have an active subscription."
            _LOGGER.warning(msg)
            return False

        url = API_URI + URL_RECORDING.format(recording_id)
        try:
            req = self._ring.query(url, raw=True)
            if req and req.status_code == 200:

                if filename:
                    if File.Exists(filename) and not override:
                        _LOGGER.error("%s", FILE_EXISTS.format(filename))
                        return False

                    with File(filename, 'wb') as recording:
                        recording.write(req.content)
                        return True
                else:
                    return req.content
        except IOError as error:
            _LOGGER.error("%s", error)
            raise
        return False

    def recording_url(self, recording_id):
        """Return HTTPS recording URL."""
        if not self.has_subscription:
            msg = "Your Ring account does not have an active subscription."
            _LOGGER.warning(msg)
            return False

        url = API_URI + URL_RECORDING.format(recording_id)
        req = self._ring.query(url, raw=True)
        if req and req.status_code == 200:
            return req.url
        return False

    @property
    def subscribed(self):
        """Return if is online."""
        result = self._attrs.get('subscribed')
        if result is None:
            return False
        return True

    @property
    def subscribed_motion(self):
        """Return if is subscribed_motion."""
        result = self._attrs.get('subscribed_motions')
        if result is None:
            return False
        return True

    @property
    def has_subscription(self):
        """Return boolean if the account has subscription."""
        return self._attrs.get('features').get('show_recordings')

    @property
    def volume(self):
        """Return volume."""
        return self._attrs.get('settings').get('doorbell_volume')

    @volume.setter
    def volume(self, value):
        if not ((isinstance(value, int)) and
                (DOORBELL_VOL_MIN <= value <= DOORBELL_VOL_MAX)):
            _LOGGER.error("%s", MSG_VOL_OUTBOUND.format(DOORBELL_VOL_MIN,
                                                        DOORBELL_VOL_MAX))
            return False

        params = {
            'doorbot[description]': self.name,
            'doorbot[settings][doorbell_volume]': str(value)}
        url = API_URI + DOORBELLS_ENDPOINT.format(self.account_id)
        self._ring.query(url, extra_params=params, method='PUT')
        self.update()
        return True

    @property
    def connection_status(self):
        """Return connection status."""
        return self._attrs.get('alerts').get('connection')

    def get_snapshot(self, retries=3, delay=1):
        """Take a snapshot and download it"""
        url = API_URI + SNAPSHOT_TIMESTAMP_ENDPOINT
        payload = {"doorbot_ids": [self._attrs.get('id')]}
        self._ring.query(url, json=payload)
        request_time = time.time()
        for _ in range(retries):
            time.sleep(delay)
            response = self._ring.query(
                url, method="POST", json=payload, raw=1).json()
            if response["timestamps"][0]["timestamp"] / 1000 > request_time:
                return self._ring.query(API_URI + SNAPSHOT_ENDPOINT.format(
                    self._attrs.get('id')), raw=True).content
        return False


class RingStickUpCam(RingDoorBell):
    """Implementation for RingStickUpCam."""

    @property
    def family(self):
        """Return Ring device family type."""
        return 'stickup_cams'

    @property
    def model(self):
        """Return Ring device model name."""
        if self.kind in FLOODLIGHT_CAM_KINDS:
            return 'Floodlight Cam'
        elif self.kind in SPOTLIGHT_CAM_BATTERY_KINDS:
            return 'Spotlight Cam {}'.format(
                self._attrs.get('ring_cam_setup_flow', 'battery').title())
        elif self.kind in SPOTLIGHT_CAM_WIRED_KINDS:
            return 'Spotlight Cam {}'.format(
                self._attrs.get('ring_cam_setup_flow', 'wired').title())
        elif self.kind in STICKUP_CAM_KINDS:
            return 'Stick Up Cam'
        elif self.kind in STICKUP_CAM_BATTERY_KINDS:
            return 'Stick Up Cam Battery'
        elif self.kind in STICKUP_CAM_WIRED_KINDS:
            return 'Stick Up Cam Wired'
        return None

    def has_capability(self, capability):
        """Return if device has specific capability."""
        if capability == 'battery':
            return self.kind in (SPOTLIGHT_CAM_BATTERY_KINDS +
                                 STICKUP_CAM_KINDS +
                                 STICKUP_CAM_BATTERY_KINDS)
        elif capability == 'light':
            return self.kind in (FLOODLIGHT_CAM_KINDS +
                                 SPOTLIGHT_CAM_BATTERY_KINDS +
                                 SPOTLIGHT_CAM_WIRED_KINDS)
        elif capability == 'siren':
            return self.kind in (FLOODLIGHT_CAM_KINDS +
                                 SPOTLIGHT_CAM_BATTERY_KINDS +
                                 SPOTLIGHT_CAM_WIRED_KINDS +
                                 STICKUP_CAM_BATTERY_KINDS +
                                 STICKUP_CAM_WIRED_KINDS)
        return False

    @property
    def lights(self):
        """Return lights status."""
        return self._attrs.get('led_status')

    @lights.setter
    def lights(self, state):
        """Control the lights."""
        values = ['on', 'off']
        if state not in values:
            _LOGGER.error("%s", MSG_ALLOWED_VALUES.format(', '.join(values)))
            return False

        url = API_URI + LIGHTS_ENDPOINT.format(self.account_id, state)
        self._ring.query(url, method='PUT')
        self.update()
        return True

    @property
    def siren(self):
        """Return siren status."""
        if self._attrs.get('siren_status'):
            return self._attrs.get('siren_status').get('seconds_remaining')
        return None

    @siren.setter
    def siren(self, duration):
        """Control the siren."""
        if not ((isinstance(duration, int)) and
                (SIREN_DURATION_MIN <= duration <= SIREN_DURATION_MAX)):
            _LOGGER.error("%s", MSG_VOL_OUTBOUND.format(SIREN_DURATION_MIN,
                                                        SIREN_DURATION_MAX))
            return False

        if duration > 0:
            state = 'on'
            params = {'duration': duration}
        else:
            state = 'off'
            params = {}
        url = API_URI + SIREN_ENDPOINT.format(self.account_id, state)
        self._ring.query(url, extra_params=params, method='PUT')
        self.update()
        return True


class RingChime(RingGeneric):
    """Implementation for Ring Chime."""

    @property
    def family(self):
        """Return Ring device family type."""
        return 'chimes'

    @property
    def model(self):
        """Return Ring device model name."""
        if self.kind in CHIME_KINDS:
            return 'Chime'
        elif self.kind in CHIME_PRO_KINDS:
            return 'Chime Pro'
        return None

    def has_capability(self, capability):
        """Return if device has specific capability."""
        if capability == 'volume':
            return True
        return False

    @property
    def volume(self):
        """Return if chime volume."""
        return self._attrs.get('settings').get('volume')

    @volume.setter
    def volume(self, value):
        if not ((isinstance(value, int)) and
                (CHIME_VOL_MIN <= value <= CHIME_VOL_MAX)):
            _LOGGER.error("%s", MSG_VOL_OUTBOUND.format(CHIME_VOL_MIN,
                                                        CHIME_VOL_MAX))
            return False

        params = {
            'chime[description]': self.name,
            'chime[settings][volume]': str(value)}
        url = API_URI + CHIMES_ENDPOINT.format(self.account_id)
        self._ring.query(url, extra_params=params, method='PUT')
        self.update()
        return True

    @property
    def linked_tree(self):
        """Return doorbell data linked to chime."""
        url = API_URI + LINKED_CHIMES_ENDPOINT.format(self.account_id)
        return self._ring.query(url)

    def test_sound(self, kind=KIND_DING):
        """Play chime to test sound."""
        if kind not in CHIME_TEST_SOUND_KINDS:
            return False
        url = API_URI + TESTSOUND_CHIME_ENDPOINT.format(self.account_id)
        self._ring.query(url, method='POST', extra_params={"kind": kind})
        return True


def _locator(lst, key, value):
    """Return the position of a match item in list."""
    try:
        return next(index for (index, d) in enumerate(lst)
                    if d[key] == value)
    except StopIteration:
        return NOT_FOUND


def _clean_cache(filename):
    """Remove filename if pickle version mismatch."""
    if File.Exists(filename):
        File.DeleteFile(filename)

    # initialize cache since file was removed
    initial_cache_data = CACHE_ATTRS
    _save_cache(initial_cache_data, filename)
    return initial_cache_data


def _exists_cache(filename):
    """Check if filename exists and if is pickle object."""
    return File.Exists(filename)


def _save_cache(data, filename):
    """Dump data into a pickle file."""
    with File(filename, 'w') as file:
        file.write(
            json.dumps(data, indent=2, sort_keys=True)
        )
    return True


def _read_cache(filename):
    """Read data from a pickle file."""
    try:
        if File.Exists(filename):
            data = json.loads(File(filename, 'r').read())

            # make sure pickle obj has the expected defined keys
            # if not reinitialize cache
            if data.keys() != CACHE_ATTRS.keys():
                raise EOFError
            return data

    except (EOFError, ValueError):
        pass
    return _clean_cache(filename)


if __name__ == '__main__':
    import creds

    ring = Ring(creds.username, creds.password)


    @event(ring, ['Connected', 'Disconnected'])
    def ConnectionEvent(interface, state):
        print('ConnectionEvent(interface={}, state{})'.format(interface, state))


    @event(ring, 'Motion')
    def MotionEvent(deviceName, evt):
        print('MotionEvent(deviceName={}, evt={})'.format(deviceName, evt))


    @event(ring, 'Ding')
    def DingEvent(deviceName, evt):
        print('DingEvent(deviceName={}, evt={})'.format(deviceName, evt))


    @event(ring, 'Other')
    def OtherEvent(deviceName, evt):
        print('OtherEvent(deviceName={}, evt={})'.format(deviceName, evt))


    print('end test')
