from django.urls import re_path

from .consumers import DashboardLiveConsumer


websocket_urlpatterns = [
    re_path(r"ws/dashboard/live/$", DashboardLiveConsumer.as_asgi()),
]
