from django.urls import path, re_path

from agentapi import mcp, rest

urlpatterns = [
    path('mcp/', mcp.endpoint, name='mcp'),
    re_path(r'^api/v1/(?P<path>.*)$', rest.dispatch, name='api_v1'),
]
