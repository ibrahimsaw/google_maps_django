from django.contrib import admin
from .models import User  # Importez le modèle User

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('pk', 'id', 'last_name', 'first_name', 'email', 'phone', 'role', 'is_active', 'is_staff', 'password')
    search_fields = ('email', 'first_name', 'last_name')
    list_filter = ('role', 'is_active', 'is_staff')

    # Active l'action de suppression multiple
    actions = ['delete_selected']
