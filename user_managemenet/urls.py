"""user_managemenet URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import routers
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions
from authentication.views import APIOverview
from authentication.api.views import reset_password, reset_password_confirm

router=routers.DefaultRouter()

schema_view = get_schema_view(
   openapi.Info(
      title="User management API",
      default_version='v1',
      description="Test description",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
#    authentication_classes=(authentication.TokenAuthentication,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', APIOverview, name = 'apioverview'),
    path('api/v1/', include('user_managemenet.routers',namespace='api')),
    path('api-auth/', include('rest_framework.urls')),
    path('authentication/', include('authentication.api.urls', namespace='authentication')),
    path('api/v1/password-reset/', reset_password, name='password-reset'),
    path('api/v1/password-reset/confirm/', reset_password_confirm, name='password-reset-confirm'),
    # path('api/v1/password-reset/', include('django_rest_passwordreset.urls', namespace='password_reset')) 
]+static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

if settings.DEBUG == True:
    urlpatterns += [
            path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
            path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    ]
