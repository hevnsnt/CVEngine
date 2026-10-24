from django.urls import path

from tenancy import views

urlpatterns = [
    path('verify/', views.verify_view, name='mfa_verify'),
    path('setup/', views.setup_view, name='mfa_setup'),
    path('disable/', views.disable_view, name='mfa_disable'),
]
