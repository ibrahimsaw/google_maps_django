# serializers.py
from rest_framework import serializers
from .models import User  # Remplacez par le nom exact de votre modèle

class AdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name',
                  'last_name',
                  'phone',
                  'email',
                  'password',
                  'role',]
        extra_kwargs = {'password': {'write_only': True}}
    def create(self, validated_data):
        # Récupérer les informations et les exclure du dictionnaire
        role = validated_data.pop('role', 'user')  # 'user' par défaut

        # Choisir la fonction de création selon le rôle
        if role == 'admin':
            return User.objects.create_superuser(**validated_data)
        else:
            return User.objects.create_user(**validated_data)
