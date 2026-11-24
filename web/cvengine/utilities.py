import re

from celery._state import get_current_task
from celery.utils.log import ColorFormatter


def get_time_taken(latest, earlier):
	duration = latest - earlier
	days, seconds = duration.days, duration.seconds
	hours = days * 24 + seconds // 3600
	minutes = (seconds % 3600) // 60
	seconds = seconds % 60
	if not hours and not minutes:
		return f'{seconds} seconds'
	elif not hours:
		return f'{minutes} minutes'
	elif not minutes:
		return f'{hours} hours'
	return f'{hours} hours {minutes} minutes'


# Logging formatters

class CVEngineTaskFormatter(ColorFormatter):

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		try:
			self.get_current_task = get_current_task
		except ImportError:
			self.get_current_task = lambda: None

	def format(self, record):
		task = self.get_current_task()
		if task and task.request:
			task_name = '/'.join(task.name.replace('tasks.', '').split('.'))
			record.__dict__.update(task_id=task.request.id,
								   task_name=task_name)
		else:
			record.__dict__.setdefault('task_name', f'{record.module}.{record.funcName}')
			record.__dict__.setdefault('task_id', '')
		return super().format(record)


def replace_nulls(obj):
	if isinstance(obj, str):
		return obj.replace("\x00", "")
	elif isinstance(obj, list):
		return [replace_nulls(item) for item in obj]
	elif isinstance(obj, dict):
		return {key: replace_nulls(value) for key, value in obj.items()}
	else:
		return obj


class SubdomainScopeChecker:
	"""
		SubdomainScopeChecker is a utility class to check if a subdomain is in scope or not.
		it supports both regex and string matching.
	"""

	def __init__(self, patterns):
		self.regex_patterns = set()
		self.plain_patterns = set()
		self.load_patterns(patterns)

	def load_patterns(self, patterns):
		"""
			Load patterns into the checker.

			Args:
				patterns (list): List of patterns to load.
			Returns: 
				None
		"""
		for pattern in patterns:
			# skip empty patterns
			if not pattern:
				continue
			try:
				self.regex_patterns.add(re.compile(pattern, re.IGNORECASE))
			except re.error:
				self.plain_patterns.add(pattern.lower())

	def is_out_of_scope(self, subdomain):
		"""
			Check if a subdomain is out of scope.

			Args:
				subdomain (str): The subdomain to check.
			Returns:
				bool: True if the subdomain is out of scope, False otherwise.
		"""
		subdomain = subdomain.lower() # though we wont encounter this, but just in case
		if subdomain in self.plain_patterns:
			return True
		return any(pattern.search(subdomain) for pattern in self.regex_patterns)


