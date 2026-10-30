from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0120_hostmove'),
    ]

    operations = [
        migrations.CreateModel(
            name='FeedWatermark',
            fields=[
                ('source', models.CharField(max_length=32, primary_key=True, serialize=False)),
                ('covered_through', models.DateTimeField(blank=True, null=True)),
                ('resume_cursor', models.TextField(blank=True, default='')),
                ('resume_head', models.DateTimeField(blank=True, null=True)),
                ('checked_at', models.DateTimeField(blank=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
