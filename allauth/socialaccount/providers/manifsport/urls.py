from allauth.socialaccount.providers.oauth2.urls import default_urlpatterns
from django.conf.urls import url
from .provider import ManifSportProvider

from .views import ManifSportLogoutView

urlpatterns = default_urlpatterns(ManifSportProvider)
urlpatterns += [
    url(r'^manifsport/logout/', ManifSportLogoutView.as_view(), name='manifsport_logout'),
]