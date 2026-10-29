from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0026_cve_guidance_budget'),
    ]

    operations = [
        migrations.AlterField(
            model_name='aiprovidersettings',
            name='provider',
            field=models.CharField(choices=[('anthropic', 'Anthropic'), ('openai', 'OpenAI'), ('openrouter', 'OpenRouter'), ('ollama', 'Ollama'), ('vllm', 'vLLM'), ('lmstudio', 'LM Studio')], default='anthropic', max_length=32),
        ),
    ]
