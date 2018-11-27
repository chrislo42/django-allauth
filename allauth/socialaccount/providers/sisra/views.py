import requests
from urllib.parse import urlencode
from django.shortcuts import reverse, redirect
from django.views.generic.base import View

from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)

from .provider import SisraProvider


class SisraOAuth2Adapter(OAuth2Adapter):
    provider_id = SisraProvider.id
    access_token_url = 'https://recette.sante-ra.fr/AutoConnectSSO/idserver/connect/token'
    authorize_url = 'https://recette.sante-ra.fr/AutoConnectSSO/idserver/connect/authorize'
    profile_url = 'https://recette.sante-ra.fr/AutoConnectSSO/idserver/connect/userinfo'

    def complete_login(self, request, app, token, **kwargs):
        resp = requests.get(self.profile_url,
                            params={'schema': 'openid',},
                            headers={'Authorization': 'Bearer %s' % token.token
                            })
        request.session['id_token'] = token.token
        request.session['state'] = request.GET['state']
        resp.raise_for_status()
        extra_data = resp.json()
        login = self.get_provider().sociallogin_from_response(request, extra_data)
        return login


oauth2_login = OAuth2LoginView.adapter_view(SisraOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(SisraOAuth2Adapter)
