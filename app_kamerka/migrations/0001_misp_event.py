from django.db import migrations, models
import jsonfield.fields

class Migration(migrations.Migration):

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='MispEvent',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('event_id', models.CharField(max_length=100)),
                ('info', models.CharField(max_length=500)),
                ('tags', models.CharField(max_length=500)),
                ('attributes', jsonfield.fields.JSONField()),
                ('device', models.ForeignKey(on_delete=models.deletion.CASCADE, to='app_kamerka.Device')),
            ],
        ),
    ]
