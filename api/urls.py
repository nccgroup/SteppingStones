from django.urls import include, path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework import routers

from api.hashmob.views import HashMobViewSet
from api.v1.views import EventStreamViewSet
from api.views import ApiRoot


hashmob_router = routers.SimpleRouter(trailing_slash=False)
hashmob_router.register(r"v2", HashMobViewSet, basename='hashmob_v2')

api_v1_router = routers.SimpleRouter()
api_v1_router.register(r"eventstream", EventStreamViewSet)

urlpatterns = [
    path('hashmob/', include(hashmob_router.urls)),
    path('v1/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('v1/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('v1/', include(api_v1_router.urls)),
    # path("api-auth/", include("rest_framework.urls", namespace="rest_framework")),
    path('', ApiRoot.as_view(), name=ApiRoot.name),
]