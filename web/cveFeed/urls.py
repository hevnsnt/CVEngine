from django.urls import path, re_path

from cveFeed import account_api, admin_api, bounty_api, settings_api, welcome

from cveFeed import views

urlpatterns = [
    path('', views.dashboard, name='cve_dashboard'),
    path('graph/', views.graph, name='cve_graph'),
    path('welcome/', views.welcome_page, name='cve_welcome'),
    re_path(r'^api/welcome/(?P<path>.*)$', welcome.dispatch, name='cve_api_welcome'),
    path('account/', views.account_page, name='cve_account'),
    path('about/', views.about_page, name='cve_about'),
    path('how-it-works/', views.how_page, name='cve_how'),
    path('admin/', views.admin_page, name='cve_admin'),
    re_path(r'^api/account/(?P<path>.*)$', account_api.dispatch, name='cve_api_account'),
    re_path(r'^api/admin/(?P<path>.*)$', admin_api.dispatch, name='cve_api_admin'),
    path('bounty/', views.bounty_page, name='cve_bounty'),
    re_path(r'^api/bounty/(?P<path>.*)$', bounty_api.dispatch, name='cve_api_bounty'),
    path('settings/', views.settings_page, name='cve_settings'),
    re_path(r'^api/settings/(?P<path>.*)$', settings_api.dispatch, name='cve_api_settings'),
    path('agents/', views.agents_page, name='cve_agents'),
    path('sentinels/', views.sentinels_page, name='cve_sentinels'),
    path('setup/', views.onboarding, name='cve_onboarding'),
    re_path(r'^(?P<slug>[-\w]+)/scans/(?P<scan_id>\d+)/$', views.scan_page, name='cve_scan'),
    re_path(r'^(?P<slug>[-\w]+)/hosts/(?P<subdomain_id>\d+)/screenshot/$', views.host_screenshot, name='cve_host_screenshot'),
    re_path(r'^(?P<slug>[-\w]+)/hosts/(?P<subdomain_id>\d+)/rdp-screenshot/(?P<port>\d+)/$', views.host_rdp_screenshot, name='cve_host_rdp_screenshot'),
    re_path(r'^(?P<slug>[-\w]+)/(?P<section>targets|scans|hosts|changes|activity|vulns|matches|hygiene|suppliers|keys)/$', views.project_page, name='cve_section'),
    path('api/feed', views.api_feed, name='cve_api_feed'),
    path('api/stats', views.api_stats, name='cve_api_stats'),
    path('api/graph', views.api_graph, name='cve_api_graph'),
    path('api/graph-live', views.api_graph_live, name='cve_api_graph_live'),
    path('api/graph-overview', views.api_graph_overview, name='cve_api_graph_overview'),
    path('api/graph-hosts', views.api_graph_hosts, name='cve_api_graph_hosts'),
    path('api/node', views.api_node, name='cve_api_node'),
    path('api/activity', views.api_activity, name='cve_api_activity'),
    path('api/discovery', views.api_discovery, name='cve_api_discovery'),
    path('api/setup/detect', views.api_detect, name='cve_api_detect'),
    path('api/setup/save', views.api_onboarding_save, name='cve_api_setup_save'),
]
