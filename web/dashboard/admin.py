from dashboard.models import *
from django.contrib import admin

admin.site.register(SearchHistory)


class ProjectMembershipInline(admin.TabularInline):
    model = ProjectMembership
    extra = 0


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'org')
    inlines = [ProjectMembershipInline]


class OrgMembershipInline(admin.TabularInline):
    model = OrgMembership
    extra = 0


@admin.register(Org)
class OrgAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'require_mfa')
    inlines = [OrgMembershipInline]


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'bugbounty_enabled', 'mfa_enabled')
    exclude = ('mfa_secret', 'recovery_codes')
admin.site.register(OpenAiAPIKey)
admin.site.register(NetlasAPIKey)
admin.site.register(ChaosAPIKey)
admin.site.register(HackerOneAPIKey)
admin.site.register(InAppNotification)
admin.site.register(UserPreferences)

@admin.register(AbuseBan)
class AbuseBanAdmin(admin.ModelAdmin):
    """Automatic bans from the input guard. Tick "lifted" to release an IP; re-enable the account from Users."""
    list_display = ('ip', 'username', 'reason', 'created_at', 'expires_at', 'lifted')
    list_filter = ('lifted',)


@admin.register(AbuseStrike)
class AbuseStrikeAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'username', 'ip', 'category', 'field', 'sample', 'weight')
    readonly_fields = [f.name for f in AbuseStrike._meta.fields]
