from django.urls import path
from pd_app import views

urlpatterns = [
    path("", views.home, name="home"),
    path("login", views.LoginView, name="LoginView"),
    path("profile", views.Profile, name="Profile")
]