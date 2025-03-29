import re
import time
from django.shortcuts import render
from django.contrib.auth import authenticate
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.utils.encoding import smart_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.hashers import check_password

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from user.models import User
from .serializers import (
    RegisterSerializer, LoginSerializer, ChangePasswordSerializer,
    PasswordResetRequestSerializer, PasswordResetSerializer
)

#Dictonariy to track togin attempts
failed_login_attempts = {}

# Dictonariy to track reset requests
password_reset_attempts = {}

DISPOSABLE_EMAIL_PROVIDERS = ["mailinator.com", "temp-mail.org", "10minutemail.com"]

def is_disposable_email(email):
    """check if the email is disposable"""
    domain_name = email.split('@')[-1]
    return domain_name in DISPOSABLE_EMAIL_PROVIDERS

def get_tokens_for_user(user):
    """generate tokens for user"""
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access),
    }

class UserRegisterView(APIView):
    """user registration logic"""
    def post(self, request, format=None):
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            validate_email(email)
        except ValidationError:
            return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)
        
        if is_disposable_email(email):
            return Response({'error': 'Disposable email are not allowed'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({'error':'User already exists.'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            validate_password(password)
        except ValidationError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({'message': 'User created successfully', 'token': token}, status=status.HTTP_201_CREATED)
        
        return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    def post(self, request, format=None):
        email = request.data.get('email')
        password = request.data.get('password')

        if not User.objects.filter(email=email).exists():
            return Response({'error': 'User with this emial does not exists'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.get(email=email)

        if user.is_active:
            return Response({'error': 'Your account is deactivated. Contact support.'}, status=status.HTTP_403_FORBIDDEN)
        
        if email in failed_login_attempts:
            attempts, last_login_time = failed_login_attempts[email]
            if attempts >= 5 - last_login_time < 300:
                return Response({'error': 'Too many login attempts. Please try again later'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
            
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(email=email, password=password)
        
        #this whole system is used to check number of failed login attempts so user can't login after 5 incorrect tries as 
        #timer increase to 5 minutes cooldown after 5 attempts
        if user:
            if email in failed_login_attempts:
                del failed_login_attempts[email]

            token = get_tokens_for_user(user)
            return Response({'message':'User loged in successfully', 'token':token}, status=status.HTTP_200_OK)
        else:
            if email in failed_login_attempts:
                failed_login_attempts[email] = (failed_login_attempts[email][0] + 1, time.time())
            else:
                failed_login_attempts[email] = (1, time.time())

            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    """Change password logic it's also uses rate limiting"""
    def post(self, request, format=None):
        serializer = ChangePasswordSerializer(data=request.data, context={'user': request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetEmailView(APIView):

    """ sends a email after for reseting password"""
    def post(self, request, format=None):
        email = request.data.get('email')

        if not User.objects.filter(email=email).exists():
            return Response({'error': 'No user found with this email'})
        
        if email in password_reset_attempts:
            attempts, last_attempt_time = password_reset_attempts[email]
            if attempts >= 3 and time.time() - last_attempt_time < 600:
                return Response({'error': 'Too many password reset attempts. Try again later.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            return Response({'message': 'Password reset link has been sent to your email'}, status=status.HTTP_200_OK)

        return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
class PasswordResetView(APIView):
    def post(self, request, uid, token, format=None):
        try:
            uid = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'error': 'Invalid reset link'}, status=status.HTTP_400_BAD_REQUEST)

        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response({'error': 'Token is invalid or has expired'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = PasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
        if serializer.is_valid():
            return Response({'message': 'Your password has been reset successfully'}, status=status.HTTP_200_OK)

        return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)