from django.urls import path,re_path
from authentication.api.views import *
from djoser import views
from rest_framework import routers

app_name = 'authentication'

urlpatterns = [
    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', UserLogoutView.as_view(), name='logout'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password-view'),
    path('token/login/', token_create),
    # re_path(r"^token/logout/?$", views.TokenDestroyView.as_view(), name="logout"),
    path('permissions/', get_user_permissions),
    path('permissions/edit/', edit_permission),
    path('group-permissions/edit/', edit_group_permission),
    path('<uidb64>/<token>/',activate, name='activate'),
    
    path('profile/', profile_api),


]