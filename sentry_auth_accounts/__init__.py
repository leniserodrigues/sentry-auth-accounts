from __future__ import absolute_import

from sentry.auth import register

from .provider import AccountsOAuth2Provider

register('accounts', AccountsOAuth2Provider)
