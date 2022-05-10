import os
from pathlib import Path
import base64

# SECURITY WARNING: don't run with debug turned on in production!
BASE_DIR = Path(__file__).resolve().parent.parent

DEBUG = False


# Database
# https://docs.djangoproject.com/en/3.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'dd11gsv0tv38j2',
        'USER': 'zlelwdltqvoeir',
        'PASSWORD': 'e2d90baf2e19aa080170b98b62056a4cd53dbbdce391722400a78923fd496900',
        'HOST': 'ec2-54-172-175-251.compute-1.amazonaws.com',
        'PORT': '5432',
    }
}


STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR,'staticfiles/')

STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static')
]

MEDIA_URL = '/media/' 
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')


EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'nirvayachaudhary6145ns@gmail.com'
EMAIL_HOST_PASSWORD = 'caliana789'