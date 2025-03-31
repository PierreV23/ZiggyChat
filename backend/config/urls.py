"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path

from chat import views

urlpatterns = [
    path('api/auth_me/', views.auth_me, name='auth_me'),
    path('api/send_message/', views.send_message, name='send_message'),
    path('api/user_login/', views.user_login, name='user_login'),
    path('api/get_messages/<str:tag>/<str:token>/<str:other_user_tag>/', views.get_messages, name='get_messages'),
    path('api/register_user/', views.register_user, name='register_user'),
    path('api/get_recent_chats/<str:tag>/<str:token>/', views.get_recent_chats, name='get_recent_chats'),
    path('api/fetch_user/<str:tag>/', views.fetch_user, name='fetch_user'),
    path('api/fetch_self/<str:tag>/<str:token>/', views.fetch_self, name='fetch_self'),
    path('api/set_hidden/<str:tag>/<str:sethid>/<str:token>/', views.set_hidden, name='set_hidden'),
    path('api/user_image/<str:tag>/', views.user_image, name='user_image'),
    path('api/update_profile_picture/', views.update_profile_picture, name='update_profile_picture'),
    path('api/user_stats/<str:tag>/<str:token>/', views.get_user_stats, name='user_stats'),
    # path("", include("chat.urls")),
    path("", views.index, name='index'),
    path("failed_auth/", views.failed_auth, name='failed_auth'),
    path("settings/", views.settings_page, name='settings_page'),
    path("register/", views.register, name='register'),
    path("login/", views.login, name='login'),
    path("chat/", include("chat.urls")),
    path('admin/', admin.site.urls),
]
