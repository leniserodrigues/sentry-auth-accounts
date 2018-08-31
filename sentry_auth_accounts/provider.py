from __future__ import absolute_import, print_function

from sentry.auth.providers.oauth2 import (
    OAuth2Callback, OAuth2Provider, OAuth2Login
)

from .constants import (
    AUTHORIZE_URL, ACCESS_TOKEN_URL, CLIENT_ID, CLIENT_SECRET, DATA_VERSION,
    SCOPE
)
from .views import FetchUser, AccountsConfigureView


class AccountsOAuth2Login(OAuth2Login):
    authorize_url = AUTHORIZE_URL
    client_id = CLIENT_ID
    scope = SCOPE

    def __init__(self, domains=None):
        self.domains = domains
        super(AccountsOAuth2Login, self).__init__()

    def get_authorize_params(self, state, redirect_uri):
        params = super(AccountsOAuth2Login, self).get_authorize_params(
            state, redirect_uri
        )
        # TODO(dcramer): ideally we could look at the current resulting state
        # when an existing auth happens, and if they're missing a refresh_token
        # we should re-prompt them a second time with ``approval_prompt=force``
        params['approval_prompt'] = 'force'
        params['access_type'] = 'offline'
        return params


class AccountsOAuth2Provider(OAuth2Provider):
    name = 'Backstage Accounts'
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET

    def __init__(self, domain=None, domains=None, version=None, **config):
        if domain:
            if domains:
                domains.append(domain)
            else:
                domains = [domain]
        self.domains = domains
        # if a domain is not configured this is part of the setup pipeline
        # this is a bit complex in Sentry's SSO implementation as we don't
        # provide a great way to get initial state for new setup pipelines
        # vs missing state in case of migrations.
        if domains is None:
            version = DATA_VERSION
        else:
            version = None
        self.version = version
        super(AccountsOAuth2Provider, self).__init__(**config)

    def get_configure_view(self):
        return AccountsConfigureView.as_view()

    def get_auth_pipeline(self):
        return [
            AccountsOAuth2Login(domains=self.domains),
            OAuth2Callback(
                access_token_url=ACCESS_TOKEN_URL,
                client_id=self.client_id,
                client_secret=self.client_secret,
            ),
            FetchUser(
                domains=self.domains,
                version=self.version,
            ),
        ]

    def get_refresh_token_url(self):
        return ACCESS_TOKEN_URL

    def build_config(self, state):
        return {
            'domains': [state['domain']],
            'version': DATA_VERSION,
        }

    def build_identity(self, state):
        # data.user => {
        #      "name": "",
        #      "surname": "",
        #      "username": "",
        #      "email": "",
        #      "picture": "",
        #      "role_ids": [],
        #      "groups": []
        # }
        data = state['data']
        user_data = state['user']

        return {
            'id': user_data['email'],
            'email': user_data['email'],
            'name': user_data['email'],
            'data': self.get_oauth_data(data),
        }
