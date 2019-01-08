import requests
import base64
import ast
from urllib.parse import urlencode
from django.shortcuts import reverse, redirect
from django.views.generic.base import View

from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)
from allauth.socialaccount.providers.oauth2.client import OAuth2Error

from .provider import SisraProvider


class SisraOAuth2Adapter(OAuth2Adapter):
    provider_id = SisraProvider.id
    access_token_url = 'https://recette.sante-ra.fr/AutoConnectSSO/idserver/connect/token'
    authorize_url = 'https://recette.sante-ra.fr/AutoConnectSSO/idserver/connect/authorize'
    profile_url = 'https://recette.sante-ra.fr/AutoConnectSSO/idserver/connect/userinfo'

    def complete_login(self, request, app, token, **kwargs):
        # Extraction et test du nonce
        # Décodage avec extra caractères pour enlever les erreurs de padding et transformation de bit en chaine puis en dict
        token_part = token.token_secret.split('.')
        data_token = ast.literal_eval(base64.urlsafe_b64decode(token_part[1] + "===").decode("utf-8"))
        if 'socialaccount_nonce' in request.session and data_token['nonce'] != request.session['socialaccount_nonce']:
            raise OAuth2Error
            return

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

    def parse_token(self, data):
        token = super().parse_token(data)
        # pas de refresh_token, utilisation de token_secret pour stocker le id_token et récupérer le nonce (et logout)
        token.token_secret = data.get('id_token', '')
        return token


oauth2_login = OAuth2LoginView.adapter_view(SisraOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(SisraOAuth2Adapter)
