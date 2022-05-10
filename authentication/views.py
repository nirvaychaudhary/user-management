from rest_framework.decorators import api_view
from rest_framework.response import Response

@api_view(['GET'])
def APIOverview(request):
	api_urls = {
        '========ALL URLs=====': '=====url path======',
		'User List':'http://127.0.0.1:8000/api/v1/users/',
		'Role Create':'http://127.0.0.1:8000/api/v1/role/',
		'Permission List':'http://127.0.0.1:8000/api/v1/perm/',
		'User Logs Update':'http://127.0.0.1:8000/api/v1/userlogs/',
		'Change Password':'http://127.0.0.1:8000/api/v1/authentication/change-password/',
		'Swagger URL':'http://127.0.0.1:8000/api/v1/swagger/', 
		'Django Redoc Swagger UI':'http://127.0.0.1:8000/api/v1/redoc/',
		'Reset Password':'http://127.0.0.1:8000/api/v1/password-reset/',
		}

	return Response(api_urls)
# http://127.0.0.1:8000/authentication/permissions/