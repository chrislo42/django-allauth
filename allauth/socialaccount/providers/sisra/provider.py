from django.utils.crypto import get_random_string
from allauth.account.models import EmailAddress
from allauth.socialaccount.app_settings import QUERY_EMAIL
from allauth.socialaccount.providers.base import AuthAction, ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider


class Scope(object):
    EMAIL = 'email'
    PROFILE = 'profile'
    OPENID = 'openid'
    pass


class SisraAccount(ProviderAccount):
    def get_profile_url(self):
        return self.account.extra_data.get('link')

    def get_avatar_url(self):
        return self.account.extra_data.get('picture')

    def to_str(self):
        dflt = super(SisraProvider, self).to_str()
        return self.account.extra_data.get('name', dflt)


class SisraProvider(OAuth2Provider):
    id = 'sisra'
    name = 'Sisra'
    account_class = SisraAccount

    def get_default_scope(self):
        scope = [Scope.OPENID]
        if QUERY_EMAIL:
            scope.append(Scope.EMAIL)
        return scope

    def get_auth_params(self, request, action):
        ret = super(SisraProvider, self).get_auth_params(request, action)
        ret['nonce'] = get_random_string()
        request.session['socialaccount_nonce'] = ret['nonce']
        if action == AuthAction.REAUTHENTICATE:
            ret['prompt'] = 'select_account consent'
        return ret

    def extract_uid(self, data):
        return str(data['portailId'])

    def extract_common_fields(self, data):

        phone = data.get('phone_number')
        if phone and phone[0] == '0':
            phone = "+33" + phone[1:]

        return dict(email=data.get('email'),
                    last_name=data.get('family_name'),
                    first_name=data.get('given_name'),
                    username=data.get('login'),
                    phone=phone)

    def extract_email_addresses(self, data):
        ret = []
        email = data.get('email')
        if email and data.get('verified_email'):
            ret.append(EmailAddress(email=email,
                       verified=True,
                       primary=True))
        return ret


provider_classes = [SisraProvider]
