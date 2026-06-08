"""
URL configuration for cti_project project.
"""

from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.views.generic import TemplateView, RedirectView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('cti/', include('cti_core.urls')),
    path('api/', include('cti_core.api_urls')),
    path('api-auth/', include('rest_framework.urls')),
    path('login/', auth_views.LoginView.as_view(template_name='login.html', next_page='/cti/'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('accounts/profile/', RedirectView.as_view(url='/cti/', permanent=False)),
    path('', TemplateView.as_view(template_name='index.html'), name='index'),
]
