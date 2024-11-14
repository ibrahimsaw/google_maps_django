import uuid
from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

"""
class Token(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    key = models.CharField(max_length=40, primary_key=True, default=uuid.uuid4, editable=False)
    created = models.DateTimeField(auto_now_add=True)
"""

class UserManager(BaseUserManager):
    def create_user(self, first_name, last_name, phone, email, password=None, role='user'):
        if not email:
            raise ValueError("L'utilisateur doit avoir une adresse email")
        if not phone:
            raise ValueError("L'utilisateur doit avoir un numéro de téléphone")

        email = self.normalize_email(email)
        user = self.model(
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            email=email,
            role=role
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, first_name, last_name, phone, email, password=None):
        user = self.create_user(
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            email=email,
            password=password,
            role='admin'
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser, PermissionsMixin):
    # Champs du modèle personnalisé
    first_name = models.CharField(max_length=50, verbose_name="Prénom")
    last_name = models.CharField(max_length=50, verbose_name="Nom")
    phone = models.CharField(max_length=15, unique=True, verbose_name="Numéro de téléphone")
    email = models.EmailField(unique=True, verbose_name="Email")
    role = models.CharField(max_length=20,
                            choices=[('user', 'Utilisateur'), ('admin', 'Administrateur'), ('moderator', 'Modérateur')],
                            default='user', verbose_name="Rôle")

    # Utilisez `related_name` pour éviter les conflits
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_groups',  # Changer related_name pour éviter les conflits
        blank=True,
        help_text="Groupes auxquels cet utilisateur appartient."
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_permissions',  # Changer related_name pour éviter les conflits
        blank=True,
        help_text="Autorisations spécifiques pour cet utilisateur."
    )

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'phone']

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "User"
        app_label = 'admins'

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.role})"



