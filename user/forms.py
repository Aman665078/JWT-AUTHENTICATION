from django.forms import forms
from user.models import User
from django.contrib.auth.forms import UserCreationForm, UserChangeForm

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = '__all__'

class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = User
        fields = '__all__'