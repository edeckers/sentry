"""
GitLab OAuth support.

This contribution adds support for GitLab OAuth service. The settings
GITLAB_APP_ID and GITLAB_API_SECRET must be defined with the values
given by GitLab application registration process.

Extended permissions are supported by defining GITLAB_EXTENDED_PERMISSIONS
setting, it must be a list of values to request.

By default account id and token expiration time are stored in extra_data
field, check OAuthBackend class for details on how to extend it.
"""
from __future__ import absolute_import

import simplejson

from django.conf import settings
from six.moves.urllib.error import HTTPError
from six.moves.urllib.parse import urlencode
from social_auth.utils import dsa_urlopen
from social_auth.backends import BaseOAuth2, OAuthBackend
from social_auth.exceptions import AuthFailed


GITLAB_BASE_ENDPOINT=getattr(settings, 'GITLAB_BASE_ENDPOINT', 'https://gitlab.com')
GITLAB_API_ENDPOINT=getattr(settings, 'GITLAB_API_ENDPOINT','https://gitlab.com/api/v4')

GITLAB_AUTHORIZATION_URL = '%s/oauth/authorize' % GITLAB_BASE_ENDPOINT
GITLAB_ACCESS_TOKEN_URL = '%s/oauth/token' % GITLAB_BASE_ENDPOINT
GITLAB_USER_DATA_URL = '%s/user' % GITLAB_API_ENDPOINT

class GitlabBackend(OAuthBackend):
    """Gitlab OAuth authentication backend"""
    name = 'gitlab'
    # Default extra data to store
    EXTRA_DATA = [
        ('id', 'id'),
        ('expires', 'expires')
    ]

    def get_user_details(self, response):
        """Return user details from Gitlab account"""
        name = response.get('name') or ''
        details = {'username': response.get('username')}

        details['email'] = response.get('email')

        try:
            # GitLab doesn't separate first and last names. Let's try.
            first_name, last_name = name.split(' ', 1)
        except ValueError:
            details['first_name'] = name
        else:
            details['first_name'] = first_name
            details['last_name'] = last_name
        return details


class GitlabAuth(BaseOAuth2):
    """Gitlab OAuth2 mechanism"""
    AUTHORIZATION_URL = GITLAB_AUTHORIZATION_URL
    ACCESS_TOKEN_URL = GITLAB_ACCESS_TOKEN_URL
    AUTH_BACKEND = GitlabBackend
    SETTINGS_KEY_NAME = 'GITLAB_APP_ID'
    SETTINGS_SECRET_NAME = 'GITLAB_API_SECRET'
    DEFAULT_SCOPE = ['read_user', 'api']

    SCOPE_VAR_NAME = 'GITLAB_EXTENDED_PERMISSIONS'

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        url = GITLAB_USER_DATA_URL + '?' + urlencode({
            'access_token': access_token
        })

        try:
            data = simplejson.load(dsa_urlopen(url))
        except ValueError:
            data = None

        return data

# Backend definition
BACKENDS = {
    'gitlab': GitlabAuth,
}
