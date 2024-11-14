
import json
from django.contrib.auth import authenticate
from django.http import JsonResponse, Http404
from django.views.decorators.csrf import csrf_exempt
from django.forms.models import model_to_dict
from django.http import JsonResponse
from django.shortcuts import render
from  .models import User
from  rest_framework.response import Response
from  rest_framework.decorators import api_view
from .serializer import AdminSerializer
from  rest_framework import generics,mixins
from django.contrib.auth import authenticate
from django.shortcuts import render
from django.http import JsonResponse
from .models import User
from django.http import JsonResponse
from django.views import View
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from django.conf import settings
from django.db import models
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from .models import User
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User

""""
def api_view(request,*args,**kwargs):
    data = {
        'name':'ibrahim',
        'language':'python'
    }
    datas = json.loads(request.body)
    print(datas)
    datas['headers'] = dict(request.headers)
    print(request.headers)
    print(request.body)
    datas['content_types'] = request.content_type
    return JsonResponse(datas)
    
"""
"""
def api_view(request):
    query = User.objects.all().order_by('?').first()
    print(User.objects.all())
    data = {}
    if query:
        #data['first_name'] = query.first_name
        #data['last_name'] = query.last_name
        #data['phone'] = query.phone
        #data['email'] = query.email
        #data['role'] = query.role
        data = model_to_dict(query,exclude=('id'))
    return JsonResponse(data)
    
"""
"""
@api_view(['POST','GET'])
def api_view(request):
    query = User.objects.all().order_by('?').first()
    print(User.objects.all())
    data = {}
    if query:
        data = model_to_dict(query,exclude=('id'))
    return Response(data)
"""
"""
@api_view(['POST'])
def api_view(request):
    data = AdminSerializer(data=request.data)
    if data.is_valid():
        data.save()
        return Response(data.data)
    else:
        # Affiche les erreurs spécifiques pour faciliter le débogage
        return Response({'details': 'invalid data', 'errors': data.errors}, status=400)
        
"""


"""
class DetailUserView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = AdminSerializer

class DetailemailUserView(generics.RetrieveAPIView):
    serializer_class = AdminSerializer

    def get_object(self):
        email = self.kwargs.get("email")
        try:
            print(User.objects.get(email=email))
            return User.objects.get(email=email)
        except User.DoesNotExist:
            raise Http404("Utilisateur non trouvé")

class DetailphoneUserView(generics.RetrieveAPIView):
    serializer_class = AdminSerializer
    def get_object(self):
        phone = self.kwargs.get("phone")
        try:
            # Recherche de l'utilisateur par email
            return User.objects.get(phone=phone)
        except User.DoesNotExist:
            raise Http404("Utilisateur non trouvé")


class UpdateUserView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = AdminSerializer
    lookup_field = 'id'  # Par défaut, utilise l'identifiant `id` pour retrouver l'utilisateur

class DeleteUserView(generics.DestroyAPIView):
    queryset = User.objects.all()
    serializer_class = AdminSerializer
    lookup_field = 'pk'  # Utilisé pour rechercher l'utilisateur à supprimer

class ListUserView(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = AdminSerializer



class UserMixinsViews(
    generics.GenericAPIView,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    mixins.ListModelMixin,
    mixins.DestroyModelMixin,
    mixins.RetrieveModelMixin):
    queryset = User.objects.all()
    serializer_class = AdminSerializer

    # Surchargez la méthode get_queryset si vous devez filtrer les utilisateurs selon certains critères
    def get_queryset(self):
        # Vous pouvez personnaliser le queryset selon vos besoins
        return super().get_queryset()

    def get(self, request, *args, **kwargs):
        # Gérer la requête GET pour lister ou récupérer des utilisateurs
        if 'pk' in kwargs:  # si une clé primaire est fournie, récupérez un utilisateur spécifique
            return self.retrieve(request, *args, **kwargs)
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        # Gérer la requête POST pour créer un utilisateur
        return self.create(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        # Gérer la requête PUT pour mettre à jour un utilisateur
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        # Gérer la requête DELETE pour supprimer un utilisateur
        return self.destroy(request, *args, **kwargs)


"""

"""
@csrf_exempt
def login_users(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        identifier = data.get('identifier')  # Peut être email ou téléphone
        password = data.get('password')

        # Vérifier si c'est un email ou un numéro de téléphone
        user = None
        if "@" in identifier:
            user = authenticate(request, email=identifier, password=password)
            print('email')
        else:
            user = authenticate(request, phone=identifier, password=password)
            print('phone')
        print(identifier)
        print(password)
        if user is not None:
            return JsonResponse({'message': 'Connexion réussie'}, status=200)
        else:
            return JsonResponse({'message': 'Identifiants incorrects'}, status=401)

    return JsonResponse({'message': 'Méthode non autorisée'}, status=405)






def login_user(request):
    if request.method == 'POST':
        identifier = request.POST.get('identifier')  # Can be email or phone
        password = request.POST.get('password')

        try:
            # Attempt to authenticate using email first
            user = User.objects.get(email=identifier)
        except User.DoesNotExist:
            # If not found by email, check by phone
            try:
                user = User.objects.get(phone=identifier)
            except User.DoesNotExist:
                return JsonResponse({'error': 'Identifiant ou mot de passe incorrect'}, status=400)

        if user.check_password(password):
            # Successful login logic here
            return JsonResponse({'message': 'Connexion réussie!'})
        else:
            return JsonResponse({'error': 'Identifiant ou mot de passe incorrect'}, status=400)
    return render(request, 'login.html')

"""


"""


class LoginView(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        identifier = data.get('identifier')  # Peut être email ou téléphone
        password = data.get('password')

        print("Identifier reçu:", identifier)
        print("Password reçu:", password)

        # Vérification de l'identifiant
        try:
            if '@' in identifier:
                user = User.objects.get(email=identifier)
                print("Utilisateur trouvé par email:", identifier)
            else:
                user = User.objects.get(phone=identifier)
                print("Utilisateur trouvé par téléphone:", identifier)
        except User.DoesNotExist:
            print("Échec : Aucun utilisateur trouvé avec cet identifiant.")
            return Response({"error": "Identifiant ou mot de passe incorrect"}, status=status.HTTP_401_UNAUTHORIZED)

        # Vérification du mot de passe
        if not user.check_password(password):
            print("Échec : Mot de passe incorrect.")
            return Response({"error": "Identifiant ou mot de passe incorrect"}, status=status.HTTP_401_UNAUTHORIZED)

        # Authentification réussie
        print("Succès : Authentification réussie.")

        # Récupérer ou créer le jeton pour cet utilisateur
        token, created = Token.objects.get_or_create(user=user)
        return Response({"token": token.key}, status=status.HTTP_200_OK)




class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Supprimer le token si l'utilisateur est authentifié
        if request.user.is_authenticated:
            try:
                request.user.auth_token.delete()
                return Response({"message": "Déconnecté avec succès"}, status=204)
            except Exception as e:
                return Response({"message": "Erreur lors de la suppression du token"}, status=500)
        return Response({"message": "Utilisateur non authentifié"}, status=403)

class SomeProtectedView(APIView):
    def get(self, request):
        if request.user.is_authenticated:
            return Response({"message": "Utilisateur connecté."})
        else:
            return Response({"message": "Utilisateur non connecté."}, status=401)

"""


from backend.user.admins.models import User




class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = AdminSerializer

    def perform_create(self, serializer):
        serializer.save()  # Sauvegarde simplement selon le rôle défini


from django.contrib.auth import get_user_model
from django.middleware.csrf import get_token
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

User = get_user_model()

@csrf_exempt  # Utilisez uniquement si nécessaire et si vous avez configuré la sécurité appropriée
def login_users(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        identifier = data.get('identifier')
        password = data.get('password')

        # Vérifier la présence des paramètres
        if not identifier or not password:
            return JsonResponse({'message': 'Identifiant ou mot de passe manquant'}, status=400)

        # Vérifier si c'est un email ou un numéro de téléphone
        user = None
        if "@" in identifier:
            user = authenticate(request, email=identifier, password=password)
            print('email')
        else:
            user = authenticate(request, phone=identifier, password=password)
            print('phone')

        print(f"Identifiant: {identifier}")
        print(f"Mot de passe: {password}")

        if user is not None:
            # Récupérer des données supplémentaires de l'utilisateur
            user_data = {
                'id': user.id,
                'first_name': user.first_name,
                'last_name' : user.last_name,
                'email': user.email,
                'phone': user.phone if hasattr(user, 'phone') else None,
                'role' : user.role,
            }

            # Générer un token CSRF (si nécessaire)
            csrf_token = get_token(request)

            return JsonResponse({
                'message': 'Connexion réussie',
                'user': user_data,
                'csrfToken': csrf_token  # Ajouter un token si nécessaire
            }, status=200)
        else:
            return JsonResponse({'message': 'Identifiants incorrects'}, status=401)

    return JsonResponse({'message': 'Méthode non autorisée'}, status=405)

"""
def login_users(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        identifier = data.get('identifier')
        password = data.get('password')

        # Vérifier la présence des paramètres
        if not identifier or not password:
            return JsonResponse({'message': 'Identifiant ou mot de passe manquant'}, status=400)

        # Vérifier si c'est un email ou un numéro de téléphone
        user = None
        if "@" in identifier:
            user = authenticate(request, email=identifier, password=password)
            print('email')
        else:
            user = authenticate(request, phone=identifier, password=password)
            print('phone')

        print(f"Identifiant: {identifier}")
        print(f"Mot de passe: {password}")

        if user is not None:
            return JsonResponse({'message': 'Connexion réussie'}, status=200)
        else:
            return JsonResponse({'message': 'Identifiants incorrects'}, status=401)

    return JsonResponse({'message': 'Méthode non autorisée'}, status=405)
"""

from django.http import JsonResponse
from django.middleware.csrf import get_token

def get_csrf_token(request):
    print("bdfb");
    return JsonResponse({'csrfToken': get_token(request)})
