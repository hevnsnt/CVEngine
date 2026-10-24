from django.urls import path

from . import views

urlpatterns = [
    path(
        'create_report/<int:id>',
        views.create_report,
        name='create_report'),
    path(
        'export/subdomains/<int:scan_id>',
        views.export_subdomains,
        name='export_subdomains'),
    path(
        'export/endpoints/<int:scan_id>',
        views.export_endpoints,
        name='export_endpoints'),
    path(
        'export/urls/<int:scan_id>',
        views.export_urls,
        name='export_http_urls'),
]
