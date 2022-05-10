from rest_framework.serializers import ModelSerializer
from authentication.models import CustomUser as User, UserLog
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.models import Group, Permission
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError
from rest_framework.exceptions import APIException
from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _

class CustomUsersSerializer(ModelSerializer):
    email = serializers.EmailField(
            required=True,
            validators=[UniqueValidator(queryset=User.objects.all())]
            )
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    class Meta:
        model = User
        fields=('id','username','password','password2', 'first_name', 'middle_name', 'last_name', 'contact_no', 'email', 'gender', 'photo', 'group', 'is_active', 'is_staff')
        read_only = ('created_at', 'is_active', 'is_staff', 'auth_provider')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs
    
    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            middle_name=validated_data['middle_name'],
            last_name=validated_data['last_name'],
            contact_no=validated_data['contact_no'],
            group=validated_data['group'],
            gender=validated_data['gender'],
            photo=validated_data['photo'],
        )

        user.set_password(validated_data['password'])
        user.is_active = True
        user.is_staff = True
        user.save() 
        return user
    
    
class UserAuthSerializer(ModelSerializer):
    class Meta:
        model = User
        fields=('id', 'username', 'first_name', 'middle_name', 'last_name', 'contact_no', 'email', 'group', 'is_active')


class PermissionSerializer(serializers.ModelSerializer):
    permission = serializers.SerializerMethodField()
    class Meta:
        ref_name="document_serializer"
        model = Permission
        fields = '__all__'

    def get_permission(self, obj):
        return obj.content_type.app_label+'.'+obj.codename
        
class GroupSerializer(serializers.ModelSerializer):
    permission = serializers.SerializerMethodField()
    class Meta:
        model = Group
        fields = '__all__'

    def get_permission(self, obj):
        return [_.content_type.app_label+'.'+_.codename for _ in obj.permissions.all()]

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(max_length=255)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            # import pdb;pdb.set_trace()
            if User.objects.filter(email=email).exists():
                user = authenticate(email=email, password=password)

                if user:
                    if user.is_active and user.is_verified:
                        data["user"] = user
                    else:
                        msg = "Please verify your email"
                        raise serializers.ValidationError(msg)
                else:
                    raise APIException({'password': ['Incorrect Password']})
            else:
                raise APIException({'email': ['Email not registered']})
        else:
            msg = "Please provide email and password"
            raise serializers.ValidationError(msg)

        return data

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128, write_only=True, required=True)
    new_password = serializers.CharField(max_length=128, write_only=True, required=True)
    confirm_password = serializers.CharField(max_length=128, write_only=True, required=True)

    def validate_old_password(self, value):
        user= self.context['request'].user
        # import pdb ; pdb.set_trace()
        if not user.check_password(value):
            raise serializers.ValidationError(_('Your old password was entered incorrectly . Please enter it again'))
            return value
    
    def validate(self,data):
        # import pdb;pdb.set_trace()
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({'confirm_password': _("The two password fields didn't match.")})
        if data['old_password'] == data['new_password']:
            # import pdb;pdb.set_trace()
            raise serializers.ValidationError({'old_password': _('New Password cannot be same as old password')})
        password_validation.validate_password(data['new_password'], self.context['request'].user)
        return data
    
    def save(self, **kwargs):
        password = self.validated_data['new_password']
        user = self.context['request'].user
        user.set_password(password)
        user.save()
        return user

class UserLogSerializer(serializers.ModelSerializer):
    
	class Meta:
		model = UserLog
		fields = "__all__"