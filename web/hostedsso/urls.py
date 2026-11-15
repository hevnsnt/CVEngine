from django.urls import path

from hostedsso import views

urlpatterns = [
    path('exchange', views.exchange, name='sso_exchange'),
    path('exchange/', views.exchange),
    path('backchannel-logout', views.backchannel_logout, name='sso_backchannel_logout'),
    path('backchannel-logout/', views.backchannel_logout),
]
