from django.contrib import admin

from app_kamerka.models import AuditLog, ScanAuthorization


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Read-only audit trail: sensitive/side-effecting operations are
    recorded by app_kamerka.views.record_audit() and should never be edited
    or deleted through the admin -- only viewed."""

    list_display = ('created_at', 'action', 'user', 'device', 'target', 'success')
    list_filter = ('action', 'success')
    search_fields = ('target', 'detail', 'user__username')
    date_hierarchy = 'created_at'
    ordering = ('-created_at',)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(ScanAuthorization)
class ScanAuthorizationAdmin(admin.ModelAdmin):
    """Engagement/authorization scopes for active operations (Nmap scanning,
    exploitation) -- see app_kamerka.authz.is_target_authorized(). Managed by
    Administrators (app_kamerka.administer capability)."""

    list_display = (
        'name', 'reference', 'cidr', 'allow_port_scan', 'allow_exploit',
        'created_by', 'created_at', 'expires_at',
    )
    list_filter = ('allow_port_scan', 'allow_exploit')
    search_fields = ('name', 'reference', 'cidr')
    readonly_fields = ('created_by', 'created_at')

    def save_model(self, request, obj, form, change):
        if not change or not obj.created_by_id:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)
