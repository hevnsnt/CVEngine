from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("cveFeed", "0105_unresolved_archive"),
        ("dashboard", "0028_apitoken_inventory_scope"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="OpenvasOrg",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("enabled", models.BooleanField(default=False)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("org", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="openvas_link", to="dashboard.org")),
                ("updated_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
