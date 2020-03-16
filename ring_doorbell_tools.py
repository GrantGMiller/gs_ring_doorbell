# coding: utf-8
# vim:sw=4:ts=4:et:
"""Python Ring Doorbell wrapper.
Based on the project: https://github.com/tchellomello/python-ring-doorbell
Modified to work within the Extron Global Scripter platform.
See example GS file: https://github.com/GrantGMiller/gs_ring_doorbell/blob/master/examples/Ring%20Doorbell%20Example.gs

Notes: make sure the time/date on your processor is set correctly and your processor can reach api.ring.com
This modules queries the ring API once per minute and triggers events. Thus your events could be up to 1 minute delayed.
An easy way to force an event is to "Go Live" with your Ring smartphone app.
    This will trigger a "Other" event.
    Of course you could also go outside and wave your hand in front of the camera, or press the doorbell button.
"""
import time
from collections import defaultdict

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

import requests
from uuid import uuid4 as uuid
from extronlib.system import File, Wait, ProgramLog
from extronlib import event
from datetime import datetime
import json

DEBUG = True
oldPrint = print
if DEBUG is False:
    print = lambda *a, **k: None


class Logger:
    def error(self, *a, **k):
        print('Logger.error:', a, k)

    def debug(self, *a, **k):
        print('Logger.debug:', *a, **k)


_LOGGER = Logger()

# coding: utf-8
# vim:sw=4:ts=4:et:
"""Constants."""
HEADERS = {
    'Content-Type': 'application/x-www-form-urlencoded; charset: UTF-8',
    'User-Agent': 'Dalvik/1.6.0 (Linux; Android 4.4.4; Build/KTU84Q)',
    'Accept-Encoding': 'gzip, deflate'
}
AUTH_HEADER = 'auth_header'
URI_QUERY = 'query'
BODY = 'body'

FORM_ENC_HEADERS = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

# number of attempts to refresh token
NUM_OF_RETRIES = 1
TIMEOUT = 5
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
    'device[metadata][language]': 'en'
}

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


class Auth:
    """A Python Auth class for Ring"""

    def __init__(self, token=None, token_updater=None):
        """
        :type token: Optional[Dict[str, str]]
        :type token_updater: Optional[Callable[[str], None]]
        """
        self.params = {'api_version': API_VERSION}

        self.token_updater = token_updater
        self._oauth = OAuth2Session(
            client=LegacyApplicationClient(client_id=OAuth.CLIENT_ID),
            token=token
        )

    def fetch_token(self, username, password, otp_code=None):
        """Initial token fetch with username/password & 2FA
        :type username: str
        :type password: str
        :type otp_code: str
        """
        if otp_code:
            headers = OAuth.HEADERS.copy()
            headers['2fa-support'] = 'true'
            headers['2fa-code'] = otp_code
        else:
            headers = OAuth.HEADERS

        token = self._oauth.fetch_token(
            OAuth.ENDPOINT,
            username=username,
            password=password,
            scope=OAuth.SCOPE,
            headers=headers
        )

        if self.token_updater is not None:
            self.token_updater(token)

        return token

    def refresh_tokens(self):
        """Refreshes the auth tokens"""
        token = self._oauth.refresh_token(
            OAuth.ENDPOINT, headers=OAuth.HEADERS
        )

        if self.token_updater is not None:
            self.token_updater(token)

        return token

    def query(self,
              url,
              method='GET',
              extra_params=None,
              json=None,
              timeout=None):
        """Query data from Ring API."""
        if timeout is None:
            timeout = TIMEOUT

        # allow to override params when necessary
        # and update self.params globally for the next connection
        if extra_params:
            params = self.params.copy()
            params.update(extra_params)
        else:
            params = self.params

        kwargs = {
            'params': params,
            'headers': OAuth.HEADERS,
            'timeout': timeout,
        }

        if method == 'POST':
            kwargs['json'] = json

        try:
            req = getattr(self._oauth, method.lower())(url, **kwargs)
        except Exception as e:
            print('254 e=', e)
            self._oauth.token = self.refresh_tokens()
            req = getattr(self._oauth, method.lower())(url, **kwargs)

        req.raise_for_status()

        return req


class Client(object):
    """Base OAuth2 client responsible for access token management.

    This class also acts as a generic interface providing methods common to all
    client types such as ``prepare_authorization_request`` and
    ``prepare_token_revocation_request``. The ``prepare_x_request`` methods are
    the recommended way of interacting with clients (as opposed to the abstract
    prepare uri/body/etc methods). They are recommended over the older set
    because they are easier to use (more consistent) and add a few additional
    security checks, such as HTTPS and state checking.

    Some of these methods require further implementation only provided by the
    specific purpose clients such as
    :py:class:`oauthlib.oauth2.MobileApplicationClient` and thus you should always
    seek to use the client class matching the RingOauth workflow you need. For
    Python, this is usually :py:class:`oauthlib.oauth2.WebApplicationClient`.

    """
    refresh_token_key = 'refresh_token'

    def __init__(self, client_id,
                 default_token_placement=AUTH_HEADER,
                 token_type='Bearer',
                 access_token=None,
                 refresh_token=None,
                 mac_key=None,
                 mac_algorithm=None,
                 token=None,
                 scope=None,
                 state=None,
                 redirect_url=None,
                 state_generator=generate_token,
                 **kwargs):
        """Initialize a client with commonly used attributes.

        :param client_id: Client identifier given by the RingOauth provider upon
        registration.

        :param default_token_placement: Tokens can be supplied in the Authorization
        header (default), the URL query component (``query``) or the request
        body (``body``).

        :param token_type: RingOauth 2 token type. Defaults to Bearer. Change this
        if you specify the ``access_token`` parameter and know it is of a
        different token type, such as a MAC, JWT or SAML token. Can
        also be supplied as ``token_type`` inside the ``token`` dict parameter.

        :param access_token: An access token (string) used to authenticate
        requests to protected resources. Can also be supplied inside the
        ``token`` dict parameter.

        :param refresh_token: A refresh token (string) used to refresh expired
        tokens. Can also be supplied inside the ``token`` dict parameter.

        :param mac_key: Encryption key used with MAC tokens.

        :param mac_algorithm:  Hashing algorithm for MAC tokens.

        :param token: A dict of token attributes such as ``access_token``,
        ``token_type`` and ``expires_at``.

        :param scope: A list of default scopes to request authorization for.

        :param state: A CSRF protection string used during authorization.

        :param redirect_url: The redirection endpoint on the client side to which
        the user returns after authorization.

        :param state_generator: A no argument state generation callable. Defaults
        to :py:meth:`oauthlib.common.generate_token`.
        """

        self.client_id = client_id
        self.default_token_placement = default_token_placement
        self.token_type = token_type
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.mac_key = mac_key
        self.mac_algorithm = mac_algorithm
        self.token = token or {}
        self.scope = scope
        self.state_generator = state_generator
        self.state = state
        self.redirect_url = redirect_url
        self.code = None
        self.expires_in = None
        self._expires_at = None
        self.populate_token_attributes(self.token)

    @property
    def token_types(self):
        """Supported token types and their respective methods

        Additional tokens can be supported by extending this dictionary.

        The Bearer token spec is stable and safe to use.

        The MAC token spec is not yet stable and support for MAC tokens
        is experimental and currently matching version 00 of the spec.
        """
        return {
            'Bearer': self._add_bearer_token,
            'MAC': self._add_mac_token
        }

    def prepare_request_uri(self, *args, **kwargs):
        """Abstract method used to create request URIs."""
        raise NotImplementedError("Must be implemented by inheriting classes.")

    def prepare_request_body(self, *args, **kwargs):
        """Abstract method used to create request bodies."""
        raise NotImplementedError("Must be implemented by inheriting classes.")

    def parse_request_uri_response(self, *args, **kwargs):
        """Abstract method used to parse redirection responses."""
        raise NotImplementedError("Must be implemented by inheriting classes.")

    def add_token(self, uri, http_method='GET', body=None, headers=None,
                  token_placement=None, **kwargs):
        """Add token to the request uri, body or authorization header.

        The access token type provides the client with the information
        required to successfully utilize the access token to make a protected
        resource request (along with type-specific attributes).  The client
        MUST NOT use an access token if it does not understand the token
        type.

        For example, the "bearer" token type defined in
        [`I-D.ietf-oauth-v2-bearer`_] is utilized by simply including the access
        token string in the request:

        .. code-block:: http

            GET /resource/1 HTTP/1.1
            Host: example.com
            Authorization: Bearer mF_9.B5f-4.1JqM

        while the "mac" token type defined in [`I-D.ietf-oauth-v2-http-mac`_] is
        utilized by issuing a MAC key together with the access token which is
        used to sign certain components of the HTTP requests:

        .. code-block:: http

            GET /resource/1 HTTP/1.1
            Host: example.com
            Authorization: MAC id="h480djs93hd8",
                                nonce="274312:dj83hs9s",
                                mac="kDZvddkndxvhGRXZhvuDjEWhGeE="

        .. _`I-D.ietf-oauth-v2-bearer`: https://tools.ietf.org/html/rfc6749#section-12.2
        .. _`I-D.ietf-oauth-v2-http-mac`: https://tools.ietf.org/html/rfc6749#section-12.2
        """
        if not is_secure_transport(uri):
            raise InsecureTransportError()

        token_placement = token_placement or self.default_token_placement

        case_insensitive_token_types = dict(
            (k.lower(), v) for k, v in self.token_types.items())
        if not self.token_type.lower() in case_insensitive_token_types:
            raise ValueError("Unsupported token type: %s" % self.token_type)

        if not (self.access_token or self.token.get('access_token')):
            raise ValueError("Missing access token.")

        if self._expires_at and self._expires_at < time.time():
            raise TokenExpiredError()

        return case_insensitive_token_types[self.token_type.lower()](uri, http_method, body,
                                                                     headers, token_placement, **kwargs)

    def prepare_authorization_request(self, authorization_url, state=None,
                                      redirect_url=None, scope=None, **kwargs):
        """Prepare the authorization request.

        This is the first step in many RingOauth flows in which the user is
        redirected to a certain authorization URL. This method adds
        required parameters to the authorization URL.

        :param authorization_url: Provider authorization endpoint URL.

        :param state: CSRF protection string. Will be automatically created if
        not provided. The generated state is available via the ``state``
        attribute. Clients should verify that the state is unchanged and
        present in the authorization response. This verification is done
        automatically if using the ``authorization_response`` parameter
        with ``prepare_token_request``.

        :param redirect_url: Redirect URL to which the user will be returned
        after authorization. Must be provided unless previously setup with
        the provider. If provided then it must also be provided in the
        token request.

        :param scope:

        :param kwargs: Additional parameters to included in the request.

        :returns: The prepared request tuple with (url, headers, body).
        """
        if not is_secure_transport(authorization_url):
            raise InsecureTransportError()

        self.state = state or self.state_generator()
        self.redirect_url = redirect_url or self.redirect_url
        self.scope = scope or self.scope
        auth_url = self.prepare_request_uri(
            authorization_url, redirect_uri=self.redirect_url,
            scope=self.scope, state=self.state, **kwargs)
        return auth_url, FORM_ENC_HEADERS, ''

    def prepare_token_request(self, token_url, authorization_response=None,
                              redirect_url=None, state=None, body='', **kwargs):
        """Prepare a token creation request.

        Note that these requests usually require client authentication, either
        by including client_id or a set of provider specific authentication
        credentials.

        :param token_url: Provider token creation endpoint URL.

        :param authorization_response: The full redirection URL string, i.e.
        the location to which the user was redirected after successfull
        authorization. Used to mine credentials needed to obtain a token
        in this step, such as authorization code.

        :param redirect_url: The redirect_url supplied with the authorization
        request (if there was one).

        :param state:

        :param body: Existing request body (URL encoded string) to embed parameters
                     into. This may contain extra paramters. Default ''.

        :param kwargs: Additional parameters to included in the request.

        :returns: The prepared request tuple with (url, headers, body).
        """
        if not is_secure_transport(token_url):
            raise InsecureTransportError()

        state = state or self.state
        if authorization_response:
            self.parse_request_uri_response(
                authorization_response, state=state)
        self.redirect_url = redirect_url or self.redirect_url
        body = self.prepare_request_body(body=body,
                                         redirect_uri=self.redirect_url, **kwargs)

        return token_url, FORM_ENC_HEADERS, body

    def prepare_refresh_token_request(self, token_url, refresh_token=None,
                                      body='', scope=None, **kwargs):
        """Prepare an access token refresh request.

        Expired access tokens can be replaced by new access tokens without
        going through the RingOauth dance if the client obtained a refresh token.
        This refresh token and authentication credentials can be used to
        obtain a new access token, and possibly a new refresh token.

        :param token_url: Provider token refresh endpoint URL.

        :param refresh_token: Refresh token string.

        :param body: Existing request body (URL encoded string) to embed parameters
                     into. This may contain extra paramters. Default ''.

        :param scope: List of scopes to request. Must be equal to
        or a subset of the scopes granted when obtaining the refresh
        token.

        :param kwargs: Additional parameters to included in the request.

        :returns: The prepared request tuple with (url, headers, body).
        """
        if not is_secure_transport(token_url):
            raise InsecureTransportError()

        self.scope = scope or self.scope
        body = self.prepare_refresh_body(body=body,
                                         refresh_token=refresh_token, scope=self.scope, **kwargs)
        return token_url, FORM_ENC_HEADERS, body

    def prepare_token_revocation_request(self, revocation_url, token,
                                         token_type_hint="access_token", body='', callback=None, **kwargs):
        """Prepare a token revocation request.

        :param revocation_url: Provider token revocation endpoint URL.

        :param token: The access or refresh token to be revoked (string).

        :param token_type_hint: ``"access_token"`` (default) or
        ``"refresh_token"``. This is optional and if you wish to not pass it you
        must provide ``token_type_hint=None``.

        :param body:

        :param callback: A jsonp callback such as ``package.callback`` to be invoked
        upon receiving the response. Not that it should not include a () suffix.

        :param kwargs: Additional parameters to included in the request.

        :returns: The prepared request tuple with (url, headers, body).

        Note that JSONP request may use GET requests as the parameters will
        be added to the request URL query as opposed to the request body.

        An example of a revocation request

        .. code-block: http

            POST /revoke HTTP/1.1
            Host: server.example.com
            Content-Type: application/x-www-form-urlencoded
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

            token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token

        An example of a jsonp revocation request

        .. code-block: http

            GET /revoke?token=agabcdefddddafdd&callback=package.myCallback HTTP/1.1
            Host: server.example.com
            Content-Type: application/x-www-form-urlencoded
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

        and an error response

        .. code-block: http

        package.myCallback({"error":"unsupported_token_type"});

        Note that these requests usually require client credentials, client_id in
        the case for public clients and provider specific authentication
        credentials for confidential clients.
        """
        if not is_secure_transport(revocation_url):
            raise InsecureTransportError()

        return prepare_token_revocation_request(revocation_url, token,
                                                token_type_hint=token_type_hint, body=body, callback=callback,
                                                **kwargs)

    def parse_request_body_response(self, body, scope=None, **kwargs):
        """Parse the JSON response body.

        If the access token request is valid and authorized, the
        authorization server issues an access token as described in
        `Section 5.1`_.  A refresh token SHOULD NOT be included.  If the request
        failed client authentication or is invalid, the authorization server
        returns an error response as described in `Section 5.2`_.

        :param body: The response body from the token request.
        :param scope: Scopes originally requested.
        :return: Dictionary of token parameters.
        :raises: Warning if scope has changed. OAuth2Error if response is invalid.

        These response are json encoded and could easily be parsed without
        the assistance of OAuthLib. However, there are a few subtle issues
        to be aware of regarding the response which are helpfully addressed
        through the raising of various errors.

        A successful response should always contain

        **access_token**
                The access token issued by the authorization server. Often
                a random string.

        **token_type**
            The type of the token issued as described in `Section 7.1`_.
            Commonly ``Bearer``.

        While it is not mandated it is recommended that the provider include

        **expires_in**
            The lifetime in seconds of the access token.  For
            example, the value "3600" denotes that the access token will
            expire in one hour from the time the response was generated.
            If omitted, the authorization server SHOULD provide the
            expiration time via other means or document the default value.

           **scope**
            Providers may supply this in all responses but are required to only
            if it has changed since the authorization request.

        .. _`Section 5.1`: https://tools.ietf.org/html/rfc6749#section-5.1
        .. _`Section 5.2`: https://tools.ietf.org/html/rfc6749#section-5.2
        .. _`Section 7.1`: https://tools.ietf.org/html/rfc6749#section-7.1
        """
        self.token = parse_token_response(body, scope=scope)
        self.populate_token_attributes(self.token)
        return self.token

    def prepare_refresh_body(self, body='', refresh_token=None, scope=None, **kwargs):
        """Prepare an access token request, using a refresh token.

        If the authorization server issued a refresh token to the client, the
        client makes a refresh request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format in the HTTP request entity-body:

        grant_type
                REQUIRED.  Value MUST be set to "refresh_token".
        refresh_token
                REQUIRED.  The refresh token issued to the client.
        scope
                OPTIONAL.  The scope of the access request as described by
                Section 3.3.  The requested scope MUST NOT include any scope
                not originally granted by the resource owner, and if omitted is
                treated as equal to the scope originally granted by the
                resource owner.
        """
        refresh_token = refresh_token or self.refresh_token
        return prepare_token_request(self.refresh_token_key, body=body, scope=scope,
                                     refresh_token=refresh_token, **kwargs)

    def _add_bearer_token(self, uri, http_method='GET', body=None,
                          headers=None, token_placement=None):
        """Add a bearer token to the request uri, body or authorization header."""
        if token_placement == AUTH_HEADER:
            headers = tokens.prepare_bearer_headers(self.access_token, headers)

        elif token_placement == URI_QUERY:
            uri = tokens.prepare_bearer_uri(self.access_token, uri)

        elif token_placement == BODY:
            body = tokens.prepare_bearer_body(self.access_token, body)

        else:
            raise ValueError("Invalid token placement.")
        return uri, headers, body

    def _add_mac_token(self, uri, http_method='GET', body=None,
                       headers=None, token_placement=AUTH_HEADER, ext=None, **kwargs):
        """Add a MAC token to the request authorization header.

        Warning: MAC token support is experimental as the spec is not yet stable.
        """
        if token_placement != AUTH_HEADER:
            raise ValueError("Invalid token placement.")

        headers = tokens.prepare_mac_header(self.access_token, uri,
                                            self.mac_key, http_method, headers=headers, body=body, ext=ext,
                                            hash_algorithm=self.mac_algorithm, **kwargs)
        return uri, headers, body

    def _populate_attributes(self, response):
        warnings.warn("Please switch to the public method "
                      "populate_token_attributes.", DeprecationWarning)
        return self.populate_token_attributes(response)

    def populate_code_attributes(self, response):
        """Add attributes from an auth code response to self."""

        if 'code' in response:
            self.code = response.get('code')

    def populate_token_attributes(self, response):
        """Add attributes from a token exchange response to self."""

        if 'access_token' in response:
            self.access_token = response.get('access_token')

        if 'refresh_token' in response:
            self.refresh_token = response.get('refresh_token')

        if 'token_type' in response:
            self.token_type = response.get('token_type')

        if 'expires_in' in response:
            self.expires_in = response.get('expires_in')
            self._expires_at = time.time() + int(self.expires_in)

        if 'expires_at' in response:
            self._expires_at = int(response.get('expires_at'))

        if 'mac_key' in response:
            self.mac_key = response.get('mac_key')

        if 'mac_algorithm' in response:
            self.mac_algorithm = response.get('mac_algorithm')


class LegacyApplicationClient(Client):
    """A public client using the resource owner password and username directly.

    The resource owner password credentials grant type is suitable in
    cases where the resource owner has a trust relationship with the
    client, such as the device operating system or a highly privileged
    application.  The authorization server should take special care when
    enabling this grant type, and only allow it when other flows are not
    viable.

    The grant type is suitable for clients capable of obtaining the
    resource owner's credentials (username and password, typically using
    an interactive form).  It is also used to migrate existing clients
    using direct authentication schemes such as HTTP Basic or Digest
    authentication to RingOauth by converting the stored credentials to an
    access token.

    The method through which the client obtains the resource owner
    credentials is beyond the scope of this specification.  The client
    MUST discard the credentials once an access token has been obtained.
    """

    grant_type = 'password'

    def __init__(self, client_id, **kwargs):
        super(LegacyApplicationClient, self).__init__(client_id, **kwargs)

    def prepare_request_body(self, username, password, body='', scope=None,
                             include_client_id=False, **kwargs):
        """Add the resource owner password and username to the request body.

        The client makes a request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format per `Appendix B`_ in the HTTP request entity-body:

        :param username:    The resource owner username.
        :param password:    The resource owner password.
        :param body: Existing request body (URL encoded string) to embed parameters
                     into. This may contain extra paramters. Default ''.
        :param scope:   The scope of the access request as described by
                        `Section 3.3`_.
        :param include_client_id: `True` to send the `client_id` in the
                                  body of the upstream request. This is required
                                  if the client is not authenticating with the
                                  authorization server as described in
                                  `Section 3.2.1`_. False otherwise (default).
        :type include_client_id: Boolean
        :param kwargs:  Extra credentials to include in the token request.

        If the client type is confidential or the client was issued client
        credentials (or assigned other authentication requirements), the
        client MUST authenticate with the authorization server as described
        in `Section 3.2.1`_.

        The prepared body will include all provided credentials as well as
        the ``grant_type`` parameter set to ``password``::

            >>> from oauthlib.oauth2 import LegacyApplicationClient
            >>> client = LegacyApplicationClient('your_id')
            >>> client.prepare_request_body(username='foo', password='bar', scope=['hello', 'world'])
            'grant_type=password&username=foo&scope=hello+world&password=bar'

        .. _`Appendix B`: https://tools.ietf.org/html/rfc6749#appendix-B
        .. _`Section 3.3`: https://tools.ietf.org/html/rfc6749#section-3.3
        .. _`Section 3.2.1`: https://tools.ietf.org/html/rfc6749#section-3.2.1
        """
        kwargs['client_id'] = self.client_id
        kwargs['include_client_id'] = include_client_id
        return prepare_token_request(self.grant_type, body=body, username=username,
                                     password=password, scope=scope, **kwargs)


def prepare_token_request(grant_type, body='', include_client_id=True, **kwargs):
    """Prepare the access token request.

    The client makes a request to the token endpoint by adding the
    following parameters using the ``application/x-www-form-urlencoded``
    format in the HTTP request entity-body:

    :param grant_type: To indicate grant type being used, i.e. "password",
                       "authorization_code" or "client_credentials".

    :param body: Existing request body (URL encoded string) to embed parameters
                 into. This may contain extra parameters. Default ''.

    :param include_client_id: `True` (default) to send the `client_id` in the
                              body of the upstream request. This is required
                              if the client is not authenticating with the
                              authorization server as described in
                              `Section 3.2.1`_.
    :type include_client_id: Boolean

    :param client_id: Unicode client identifier. Will only appear if
                      `include_client_id` is True. *

    :param client_secret: Unicode client secret. Will only appear if set to a
                          value that is not `None`. Invoking this function with
                          an empty string will send an empty `client_secret`
                          value to the server. *

    :param code: If using authorization_code grant, pass the previously
                 obtained authorization code as the ``code`` argument. *

    :param redirect_uri: If the "redirect_uri" parameter was included in the
                         authorization request as described in
                         `Section 4.1.1`_, and their values MUST be identical. *

    :param kwargs: Extra arguments to embed in the request body.

    Parameters marked with a `*` above are not explicit arguments in the
    function signature, but are specially documented arguments for items
    appearing in the generic `**kwargs` keyworded input.

    An example of an authorization code token request body:

    .. code-block:: http

        grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
        &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb

    .. _`Section 4.1.1`: https://tools.ietf.org/html/rfc6749#section-4.1.1
    """
    params = [('grant_type', grant_type)]

    if 'scope' in kwargs:
        kwargs['scope'] = list_to_scope(kwargs['scope'])

    # pull the `client_id` out of the kwargs.
    client_id = kwargs.pop('client_id', None)
    if include_client_id:
        if client_id is not None:
            params.append((unicode_type('client_id'), client_id))

    # the kwargs iteration below only supports including boolean truth (truthy)
    # values, but some servers may require an empty string for `client_secret`
    client_secret = kwargs.pop('client_secret', None)
    if client_secret is not None:
        params.append((unicode_type('client_secret'), client_secret))

    # this handles: `code`, `redirect_uri`, and other undocumented params
    for k in kwargs:
        if kwargs[k]:
            params.append((unicode_type(k), kwargs[k]))

    return add_params_to_qs(body, params)


class OAuth:
    """RingOauth class constants"""
    ENDPOINT = 'https://oauth.ring.com/oauth/token'
    CLIENT_ID = 'ring_official_android'
    SCOPE = ['client']
    HEADERS = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9.0;'
                      'SM-G850F Build/LRX22G)'
    }


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

        self._scriptStartDT = datetime.utcnow()  # ignore events that happen before this DT
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
            try:
                self._authenticate()
            except:
                ProgramLog('Ring failed to authenticate.', 'error')
                pass

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

        if not self.is_connected:
            try:
                self._authenticate()
            except:
                self._wait_Update.Restart()
                return

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

        response = self.session.post(
            OAUTH_ENDPOINT,
            data=oauth_data,
            headers=HEADERS
        )
        oauth_token = None
        if response.status_code == 200:
            oauth_token = response.json().get('access_token')
        return oauth_token

    def _authenticate(self, attempts=NUM_OF_RETRIES, session=None):
        """Authenticate user against Ring API."""
        url = API_URI + NEW_SESSION_ENDPOINT
        loop = 0
        while loop <= attempts:
            HEADERS['Authorization'] = \
                'Bearer {}'.format(self._get_oauth_token())
            loop += 1
            try:
                if session is None:
                    req = self.session.post(
                        url,
                        data=POST_DATA,
                        headers=HEADERS
                    )
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
        if not req.ok:
            print('req.reason=', req.reason)
            print('req.text=', req.text)
        # req.raise_for_status()
        return req.ok

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
              attempts=NUM_OF_RETRIES,
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
                    resp = self.session.get(url, params=urlencode(params))
                elif method == 'PUT':
                    resp = self.session.put(url, params=urlencode(params))
                elif method == 'POST':
                    resp = self.session.post(
                        url, params=urlencode(params), json=json)

                if self.debug:
                    _LOGGER.debug("_query %s ret %s", loop, resp.status_code)

            except requests.exceptions.RequestException as err_msg:
                _LOGGER.error("Error!! %s", err_msg)
                raise

            # if token is expired, refresh credentials and try again
            if resp.status_code == 401:
                self._NewConnectionStatus(False)
                self._authenticate()
                continue

            if resp.status_code == 200 or resp.status_code == 204:
                # if raw, return session object otherwise return JSON
                if raw:
                    response = resp
                else:
                    if method == 'GET':
                        response = resp.json()
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

            for entry in response:
                utc_dt = datetime.strptime(
                    entry['created_at'],
                    '%Y-%m-%dT%H:%M:%S.000Z'
                )
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

    ring = Ring(creds.username, creds.password, debug=True)
    oldPrint('Devices=', ring.devices.values())


    @event(ring, 'TwoFactorAuthenticationRequired')
    def TwoFactorEvent(interface, _):
        print('Please enter your 2FA code.')
        code = int(input('Enter your 2FA code.'))
        ring.Submit2FACode(code)


    @event(ring, ['Connected', 'Disconnected'])
    def ConnectionEvent(interface, state):
        oldPrint('ConnectionEvent(interface={}, state={})'.format(interface, state))


    @event(ring, 'Motion')
    def MotionEvent(deviceName, evt):
        oldPrint('MotionEvent(deviceName={}, evt={})'.format(deviceName, evt))


    @event(ring, 'Ding')
    def DingEvent(deviceName, evt):
        oldPrint('DingEvent(deviceName={}, evt={})'.format(deviceName, evt))


    @event(ring, 'Other')
    def OtherEvent(deviceName, evt):
        oldPrint('OtherEvent(deviceName={}, evt={})'.format(deviceName, evt))


    oldPrint('end test script. waiting for events')
