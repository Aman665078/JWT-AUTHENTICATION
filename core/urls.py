from django.urls import path
from .views import UserRegisterView, UserLoginView, PasswordResetView, ChangePasswordView, PasswordResetEmailView
urlpatterns = [
    path('register/', UserRegisterView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('email/', PasswordResetEmailView.as_view(), name='email'),
    path('reset-password/', PasswordResetView.as_view(), name='reset_password'),
]
