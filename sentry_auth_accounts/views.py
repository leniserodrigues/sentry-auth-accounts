from __future__ import absolute_import, print_function

import logging

from requests import HTTPError

from sentry.auth.view import AuthView, ConfigureView
from sentry.http import safe_urlopen, safe_urlread
from sentry.utils import json

from urllib import urlencode

from .constants import (
    DOMAIN_BLOCKLIST, ERR_INVALID_DOMAIN, ERR_INVALID_RESPONSE, USER_DETAILS_ENDPOINT
)

logger = logging.getLogger('sentry.auth.accounts')


class FetchUser(AuthView):
    def __init__(self, domains, version, *args, **kwargs):
        self.domains = domains
        self.version = version
        super(FetchUser, self).__init__(*args, **kwargs)

    def dispatch(self, request, helper):
        data = helper.fetch_state('data')

        try:
            access_token = helper.fetch_state('data')['access_token']
            req = safe_urlopen(USER_DETAILS_ENDPOINT, method='GET', headers={'Authorization': 'Bearer ' + access_token})
            if req.status_code != 200:
                raise HTTPError
        except HTTPError:
            logger.error('Request to %s returned %s' % (USER_DETAILS_ENDPOINT, req.reason))
            return helper.error(ERR_INVALID_RESPONSE)
        except KeyError:
            logger.error('Unable to catch information.')
            return helper.error(ERR_INVALID_RESPONSE)

        try:
            payload = req.json()
        except Exception as exc:
            logger.error('Unable to catch response as json %s' % exc, exc_info=True)
            return helper.error(ERR_INVALID_RESPONSE)

        if not payload.get('email'):
            logger.error('Missing email in user_info payload: %s' % payload)
            return helper.error(ERR_INVALID_RESPONSE)

        domain = extract_domain(payload['email'])

        if domain is None:
            logger.error('No domain found')
            return helper.error(ERR_INVALID_DOMAIN % (domain,))

        if domain in DOMAIN_BLOCKLIST:
            logger.error('Domain not allowed')
            return helper.error(ERR_INVALID_DOMAIN % (domain,))

        if self.domains and domain not in self.domains:
            return helper.error(ERR_INVALID_DOMAIN % (domain,))

        helper.bind_state('domain', domain)
        helper.bind_state('user', payload)

        return helper.next_step()


class AccountsConfigureView(ConfigureView):
    def dispatch(self, request, organization, auth_provider):
        config = auth_provider.config
        if config.get('domain'):
            domains = [config['domain']]
        else:
            domains = config.get('domains')
        return self.render('sentry_auth_accounts/configure.html', {
            'domains': domains or [],
        })


def extract_domain(email):
    return email.rsplit('@', 1)[-1]
