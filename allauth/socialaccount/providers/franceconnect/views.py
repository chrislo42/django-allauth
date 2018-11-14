import requests
from urllib.parse import urlencode
from django.shortcuts import reverse, redirect
from django.views.generic.base import View

from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)

from .provider import FranceConnectProvider


class FranceConnectOAuth2Adapter(OAuth2Adapter):
    provider_id = FranceConnectProvider.id
    access_token_url = 'https://fcp.integ01.dev-franceconnect.fr/api/v1/token'
    authorize_url = 'https://fcp.integ01.dev-franceconnect.fr/api/v1/authorize'
    profile_url = 'https://fcp.integ01.dev-franceconnect.fr/api/v1/userinfo'

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


class FranceConnectLogoutView(View):
    logout_url = 'https://fcp.integ01.dev-franceconnect.fr/api/v1/logout'
    def get(self, request):
        id_token = request.session['id_token']
        state = request.session['state']
        data = {
            'id_token_hint': id_token,
            'state': state,
            'post_logout_redirect_uri': request.build_absolute_uri('/accounts/logout/'),
        }
        return redirect(self.logout_url + '?' + urlencode(data))

oauth2_login = OAuth2LoginView.adapter_view(FranceConnectOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(FranceConnectOAuth2Adapter)
