from django.contrib import admin

from app_kamerka.models import AuditLog


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
