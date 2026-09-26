"""Data migration: create the Viewer / Analyst / Active Scanner / Exploit
Operator / Administrator groups, cumulatively granted the custom
permissions declared on Device.Meta.permissions (see
0006_alter_device_options_alter_auditlog_action_and_more and
app_kamerka.authz). An operator assigns a user to one of these groups via
Django admin (Users -> pick user -> Groups) to grant that role; a
superuser already holds every permission implicitly and needs no group.
"""
from django.apps import apps as global_apps
from django.contrib.auth.management import create_permissions
from django.db import migrations

# codename -> which groups get it (cumulative, per the S4 architecture-review
# capability mapping).
GROUP_PERMISSIONS = {
    'Viewer': ['view_capability'],
    'Analyst': ['view_capability', 'run_search'],
    'Active Scanner': ['view_capability', 'run_search', 'active_scan'],
    'Exploit Operator': ['view_capability', 'run_search', 'active_scan', 'exploit'],
    'Administrator': ['view_capability', 'run_search', 'active_scan', 'exploit', 'administer'],
}


def create_groups(apps, schema_editor):
    # The custom permissions declared on Device.Meta.permissions are normally
    # created by django.contrib.auth's create_permissions post_migrate
    # signal, which only fires once ALL migrations in this run have applied
    # -- i.e. after this data migration has already run. Force it to run now
    # (for this app only, against the historical migration state) so the
    # Permission rows we need below actually exist yet.
    app_config = global_apps.get_app_config('app_kamerka')
    create_permissions(app_config, apps=apps, verbosity=0)

    Group = apps.get_model('auth', 'Group')
    Permission = apps.get_model('auth', 'Permission')
    ContentType = apps.get_model('contenttypes', 'ContentType')
    Device = apps.get_model('app_kamerka', 'Device')

    content_type = ContentType.objects.get_for_model(Device)

    for group_name, codenames in GROUP_PERMISSIONS.items():
        group, _ = Group.objects.get_or_create(name=group_name)
        perms = Permission.objects.filter(content_type=content_type, codename__in=codenames)
        group.permissions.set(perms)


def delete_groups(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Group.objects.filter(name__in=GROUP_PERMISSIONS.keys()).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('app_kamerka', '0006_alter_device_options_alter_auditlog_action_and_more'),
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.RunPython(create_groups, delete_groups),
    ]
