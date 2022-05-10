from rest_framework.decorators import api_view
from rest_framework.response import Response

@api_view(['GET'])
def APIOverview(request):
	api_urls = {
        '========ALL URLs=====': '=====url path======',
		'User List':'https://user-managing.herokuapp.com/api/v1/users/',
		'Role Create':'https://user-managing.herokuapp.com/api/v1/role/',
		'Permission List':'https://user-managing.herokuapp.com/api/v1/perm/',
		'User Logs Update':'https://user-managing.herokuapp.com/api/v1/userlogs/',
		'Change Password':'https://user-managing.herokuapp.com/authentication/change-password/',
		'Swagger URL':'https://user-managing.herokuapp.com/swagger/', 
		'Django Redoc Swagger UI':'https://user-managing.herokuapp.com/redoc/',
		'Reset Password':'https://user-managing.herokuapp.com/api/v1/password-reset/',
		'Login': 'https://user-managing.herokuapp.com/authentication/login/',
		'Logout': 'https://user-managing.herokuapp.com/authentication/logout/',
		
		'========Password Reset Instruction=====': '=====url path======',
		'go to the link':'https://user-managing.herokuapp.com/api/v1/password-reset/',
		'add email in json format':'{ "email":"enter your valid email address"}',
		'check email address': 'open your gmail and check the latest password reset email',
		'open password reset email':'click on reset button and open it in new tab',
		'after opening link on new tab': 'refresh the page',
		'at the final': 'provide data in json format as {"password":"new password", "confirm_password":"retype new password"} and submit it',

		'========Password Change Instruction=====': '=====url path======',
		'go to the link': 'https://user-managing.herokuapp.com/authentication/change-password/',
		'type': 'old password, new password and confirm new password',

		'========API Documentation link=====': '=====url path======',	
		'using swagger UI': 'https://user-managing.herokuapp.com/swagger/',
		'from OPENAPI (fka swagger UI)': 'https://user-managing.herokuapp.com/redoc/',	
		}

	return Response(api_urls)