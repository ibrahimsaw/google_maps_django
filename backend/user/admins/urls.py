"""
from django.urls import path
from django.contrib.auth import views as auth_views

from .views import CreateUserView,api_view ,DetailUserView ,\
    CreateUserView,ListUserView,UpdateUserView,\
    DeleteUserView, UserMixinsViews,LoginView,LogoutView,\
    DetailemailUserView,DetailphoneUserView,
app_name = "posts"

urlpatterns = [

    path('', api_view, name="api_view"),
    path('<int:pk>/',DetailUserView.as_view()),
    path('sin/phone/<str:phone>/',DetailphoneUserView.as_view()),
    path('sin/email/<str:email>/',DetailemailUserView.as_view()),
    path('create/', CreateUserView.as_view(), name='admin-create'),
    path('list/', ListUserView.as_view(), name='user-list'),
    path('update/<int:id>/', UpdateUserView.as_view(), name='admin-update'),
    path('delete/<int:pk>/', DeleteUserView.as_view(), name='admin-delete'),
    # Chemin pour lister tous les utilisateurs
    path('user/list/', UserMixinsViews.as_view(), name='user-list'),
    # Chemin pour créer un nouvel utilisateur
    path('user/create/', UserMixinsViews.as_view(), name='user-create'),
    # Chemin pour récupérer les détails d'un utilisateur spécifique (requête GET avec pk)
    path('user/<str:email>/', UserMixinsViews.as_view(), name='user-detail'),
    # Chemin pour mettre à jour un utilisateur spécifique (requête PUT avec pk)
    path('user/update/<int:pk>/', UserMixinsViews.as_view(), name='user-update'),
    # Chemin pour supprimer un utilisateur spécifique (requête DELETE avec pk)
    path('user/delete/<int:pk>/', UserMixinsViews.as_view(), name='user-delete'),
    #path('login/', auth_views.LoginView.as_view(), name='login'),
    path('login/', LoginView.as_view(), name='login_user'),
    path('logout/', LogoutView.as_view(), name='logout_user'),
    path('create/', CreateUserView.as_view(), name='admin-create'),
]
"""

from django.urls import path

from backend.user.admins.views import CreateUserView,login_users,get_csrf_token

urlpatterns = [
    path('create/', CreateUserView.as_view(), name='admin-create'),
    path('login/', login_users, name='login_user'),
    path('csrf/', get_csrf_token, name='csrf'),
]