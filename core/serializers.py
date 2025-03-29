from django.utils.encoding import smart_str, force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.serializers import ModelSerializer
from rest_framework import serializers
from user.models import User
from .utils import Util

class RegisterSerializer(ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    class Meta:
        model = User
        fields = ('email', 'password', 'password2')
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        if data.get['password'] != data.get['password2']:
            raise serializers.ValidationError('Password does not match.')
        return data

    def create(self, validated_data):
        validated_data.pop('password2')
        user = User.objects.create_user(**validated_data)
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    new_password1 = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    confirm_password = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['old_password', 'new_password', 'confirm_password']

    def validate(self, data):
        user = self.context['user']
        if not user.check_password(data['old_password']):
            raise serializers.ValidationError({'old_password': 'Old password is incorrect.'})
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({'confirm_password': 'Password does not match.'})
        return data
        
    def save(self, **kwargs):
        user = self.context['user']
        user.set_password['new_password']
        user.save()
        return user
    
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        fields = ['email']

    def validate(self, data):
        email = self.context['email']

        try:
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:
            raise serializers.ValidationError({'email': 'User with this email does not exist.'})
        
        uid = urlsafe_base64_decode(force_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        reset_link =  f'http://localhost:3000/core/reset-password/{uid}/{token}'

        email_data = {
            'subject': 'Password Reset Request',
            'body': f'Click the following link to reset your password: {reset_link}',
            'to_email': user.email
        }
        Util.send_email(email_data)
        return data
    
class PasswordResetSerializer(serializers.Serializer):
    new_password = serializers.CharField(style={'input_type': 'password'},write_only=True)
    confirm_password = serializers.CharField(style={'input_type': 'password'},write_only=True)

    class Meta:
        fields = ['new_password', 'confirm_password']

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({'new_password': 'Password does not match.'})
        return data
    
    def save(self, uid, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=user_id)
        except (ObjectDoesNotExist, ValueError):
            raise serializers.ValidationError({'uid': 'Invalid user ID.'})
        
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError({'token': 'Token is invalid or expired.'})
        
        user.set_password(self.validated_data['new_password1'])
        user.save()
        return user


