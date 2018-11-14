from allauth.socialaccount.providers.oauth2.urls import default_urlpatterns
from django.conf.urls import url
from .provider import FranceConnectProvider

from .views import FranceConnectLogoutView

urlpatterns = default_urlpatterns(FranceConnectProvider)
urlpatterns += [
    url(r'^franceconnect/logout/', FranceConnectLogoutView.as_view(), name='franceconnect_logout'),
]