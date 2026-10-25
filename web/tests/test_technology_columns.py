from django.test import TestCase

from startScan.models import Technology


class TechnologyColumnsTests(TestCase):
	def test_version_and_category_follow_the_name(self):
		php = Technology.objects.create(name='PHP:8.2.30')
		self.assertEqual((php.version, php.category), ('8.2.30', 'language'))
		nginx = Technology.objects.create(name='nginx')
		self.assertEqual((nginx.version, nginx.category), ('', 'web server'))
		self.assertEqual(Technology.objects.create(name='Mystery Widget').category, '')

	def test_renaming_updates_the_columns_even_with_update_fields(self):
		tech = Technology.objects.create(name='WordPress')
		tech.name = 'Drupal:10.1'
		tech.save(update_fields=['name'])
		tech.refresh_from_db()
		self.assertEqual((tech.version, tech.category), ('10.1', 'cms'))

	def test_the_database_can_filter_on_category(self):
		Technology.objects.create(name='WordPress:6.4')
		Technology.objects.create(name='PHP')
		self.assertEqual(list(Technology.objects.filter(category='cms').values_list('name', flat=True)), ['WordPress:6.4'])
