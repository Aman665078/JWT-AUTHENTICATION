from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError

class UserManager(BaseUserManager):
    """custom user manager"""
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            return ValidationError('Email is required to create account')
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        """creation of superuser with extra permissions"""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)
    

class User(AbstractBaseUser, PermissionsMixin):
    """ Custom User creation models """
    email = models.EmailField(_("Email"), max_length=254, unique=True)
    username = models.CharField(_("Username"), max_length=80)
    is_active = models.CharField(_("Active"), max_length=50, default=True)
    is_staff = models.CharField(_("Staff"), max_length=50, default=False)
    date_joined = models.DateTimeField(_(""), auto_now_add=True)
    last_login = models.DateTimeField(_("Last Login"), auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        """Returns a string representation of the user"""
        return self.email

    def deactivate_user(self):
        """Deactivates the user account"""
        self.is_active = False
        self.save()

    def activate_user(self):
        """Activates the user account"""
        self.is_active = True
        self.save()