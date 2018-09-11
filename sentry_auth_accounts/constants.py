from __future__ import absolute_import, print_function

from django.conf import settings


AUTHORIZE_URL = getattr(settings, 'ACCOUNTS_AUTHORIZE_URL', None)

ACCESS_TOKEN_URL = getattr(settings, 'ACCOUNTS_ACCESS_TOKEN_URL', None)

CLIENT_ID = getattr(settings, 'ACCOUNTS_CLIENT_ID', None)

CLIENT_SECRET = getattr(settings, 'ACCOUNTS_CLIENT_SECRET', None)

USER_DETAILS_ENDPOINT = getattr(settings, 'ACCOUNTS_USER_DETAILS_URL', None)

ERR_INVALID_DOMAIN = 'The domain for your account (%s) is not allowed to authenticate with this provider.'

ERR_INVALID_RESPONSE = 'Unable to fetch user information from Backstage Accounts.'

SCOPE = 'email'

DOMAIN_BLOCKLIST = frozenset(getattr(settings, 'ACCOUNTS_DOMAIN_BLOCKLIST', []) or [])

DATA_VERSION = '1'
