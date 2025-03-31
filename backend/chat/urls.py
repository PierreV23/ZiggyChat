from django.urls import path

from . import views

urlpatterns = [
    path("", views.chat, name="chat"),
    # path("chat", views.chat, name="chat"),
]