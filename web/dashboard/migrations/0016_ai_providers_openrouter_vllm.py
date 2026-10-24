from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0015_abuse_guard'),
    ]

    operations = [
        migrations.AlterField(
            model_name='aiprovidersettings',
            name='provider',
            field=models.CharField(choices=[('anthropic', 'Anthropic'), ('openai', 'OpenAI'), ('openrouter', 'OpenRouter'), ('ollama', 'Ollama'), ('vllm', 'vLLM')], default='anthropic', max_length=32),
        ),
    ]
