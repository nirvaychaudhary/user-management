from django.urls import path, include
from authentication.api.views import *
from rest_framework import routers

app_name = 'api'

router=routers.DefaultRouter()
# router.register(r'register', UserRegister, 'register')
router.register(r'users', UserAPIView, basename='users')
router.register(r'role', GroupAPIView, basename='role')
router.register(r'perm', PermissionView, basename='perm')
router.register(r'userlogs', UserLogView, basename='user-logs')

urlpatterns = [
	path('', include(router.urls)),
]