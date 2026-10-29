import functools
import whatportis
import socket
import json
import os
import pickle
import re
import random
import glob
import shutil
import traceback
import ipaddress
import humanize
import redis
import requests
import tldextract
import xmltodict

from time import sleep
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from celery.utils.log import get_task_logger
from discord_webhook import DiscordEmbed, DiscordWebhook
from django.db.models import Q
from dotted_dict import DottedDict

from reNgine.definitions import *
from reNgine.settings import *
from scanEngine.models import *
from dashboard.models import *
from startScan.models import *
from targetApp.models import *
from reNgine.utilities import is_valid_url


logger = get_task_logger(__name__)
DISCORD_WEBHOOKS_CACHE = redis.Redis.from_url(CELERY_BROKER_URL)


def _seal(obj):
    """Pickle ``obj`` for the Discord cache with a signature: the cache lives in Redis, and unpickling whatever is found there would
    run code for anyone who can write to it. Only blobs signed with this installation's secret are read back."""
    from django.utils.crypto import salted_hmac
    blob = pickle.dumps(obj)
    return salted_hmac('reNgine.discord-cache', blob).digest() + blob


def _unseal(sealed):
    """The object ``_seal`` stored, or None for anything that is missing, altered or not signed by this installation."""
    from django.utils.crypto import constant_time_compare, salted_hmac
    if not isinstance(sealed, (bytes, bytearray)) or len(sealed) <= 20:
        return None
    mac, blob = bytes(sealed[:20]), bytes(sealed[20:])
    if not constant_time_compare(mac, salted_hmac('reNgine.discord-cache', blob).digest()):
        return None
    try:
        return pickle.loads(blob)
    except Exception:  # noqa: BLE001 - a blob of an older shape is a cache miss
        return None

#------------------#
# EndPoint queries #
#------------------#


#-----------#
# URL utils #
#-----------#


#-------#
# Utils #
#-------#


def remove_ansi_escape_sequences(text):
	# Regular expression to match ANSI escape sequences
	ansi_escape_pattern = r'\x1b\[.*?m'

	# Use re.sub() to replace the ANSI escape sequences with an empty string
	plain_text = re.sub(ansi_escape_pattern, '', text)
	return plain_text


#--------------------#
# NOTIFICATION UTILS #
#--------------------#

class NotificationError(RuntimeError):
	"""A notification could not be sent. Its text never contains the webhook URL or the bot token."""


def hide_webhook_errors(channel):
	"""Decorator for the senders below. A webhook URL (Slack, Discord, Lark) and a Telegram bot token are bearer credentials, and a
	``requests`` or discord-webhook exception carries the full URL in its message and its traceback, which Celery logs. Any failure
	is replaced by a NotificationError that names the channel, the exception type and the HTTP status, with the original exception
	dropped from the chain (not chained, not in the traceback)."""
	def decorate(fn):
		@functools.wraps(fn)
		def wrapper(*args, **kwargs):
			kind = status = None
			try:
				return fn(*args, **kwargs)
			except NotificationError:
				raise
			except Exception as exc:  # noqa: BLE001
				kind = type(exc).__name__
				status = getattr(getattr(exc, 'response', None), 'status_code', None)
			error = NotificationError(f'{channel} notification failed ({kind}' + (f', HTTP {status}' if status else '') + ')')
			error.__suppress_context__ = True
			raise error from None
		return wrapper
	return decorate


@hide_webhook_errors('telegram')
def send_telegram_message(message):
	"""Send Telegram message.

	Args:
		message (str): Message.
	"""
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_telegram and
		notif.telegram_bot_token and
		notif.telegram_bot_chat_id)
	if not do_send:
		return
	telegram_bot_token = notif.telegram_bot_token
	telegram_bot_chat_id = notif.telegram_bot_chat_id
	# params= percent-encodes the message, so finding or tech names (attacker-influenced) cannot add query parameters
	requests.get(
		f'https://api.telegram.org/bot{telegram_bot_token}/sendMessage',
		params={'chat_id': telegram_bot_chat_id, 'parse_mode': 'Markdown', 'text': message},
		timeout=30)


@hide_webhook_errors('slack')
def send_slack_message(message):
	"""Send Slack message.

	Args:
		message (str): Message.
	"""
	headers = {'content-type': 'application/json'}
	message = {'text': message}
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_slack and
		notif.slack_hook_url)
	if not do_send:
		return
	hook_url = notif.slack_hook_url
	requests.post(url=hook_url, data=json.dumps(message), headers=headers, timeout=30)

@hide_webhook_errors('lark')
def send_lark_message(message):
	"""Send lark message.

	Args:
		message (str): Message.
	"""
	headers = {'content-type': 'application/json'}
	message = {"msg_type":"interactive","card":{"elements":[{"tag":"div","text":{"content":message,"tag":"lark_md"}}]}}
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_lark and
		notif.lark_hook_url)
	if not do_send:
		return
	hook_url = notif.lark_hook_url
	requests.post(url=hook_url, data=json.dumps(message), headers=headers, timeout=30)

@hide_webhook_errors('discord')
def send_discord_message(
		message,
		title='',
		severity=None,
		url=None,
		files=None,
		fields={},
		fields_append=[],
		_attempt=0):
	"""Send Discord message.

	If title and fields are specified, ignore the 'message' and create a Discord
	embed that can be updated later if specifying the same title (title is the
	cache key).

	Args:
		message (str): Message to send. If an embed is used, this is ignored.
		severity (str, optional): Severity. Colors are picked based on severity.
		files (list, optional): List of files to attach to message.
		title (str, optional): Discord embed title.
		url (str, optional): Discord embed URL.
		fields (dict, optional): Discord embed fields.
		fields_append (list, optional): Discord embed field names to update
			instead of overwrite.
	"""

	# Check if do send
	notif = Notification.objects.first()
	if not (notif and notif.send_to_discord and notif.discord_hook_url):
		return False

	# If fields and title, use an embed
	use_discord_embed = fields and title
	if use_discord_embed:
		message = '' # no need for message in embeds

	# Check for cached response in cache, using title as key
	cached_response = _unseal(DISCORD_WEBHOOKS_CACHE.get(title)) if title else None

	# The webhook is built from the stored setting every time: its URL is a secret and is never kept in the cache.
	webhook = DiscordWebhook(
		url=notif.discord_hook_url,
		rate_limit_retry=False,
		timeout=30,
		content=message)

	# Get existing embed if found in cache
	embed = None
	cached_embed = _unseal(DISCORD_WEBHOOKS_CACHE.get(title + '_embed')) if title else None
	if cached_embed:
		embed = cached_embed
	elif use_discord_embed:
		embed = DiscordEmbed(title=title)

	# Set embed fields
	if embed:
		if url:
			embed.set_url(url)
		if severity:
			embed.set_color(DISCORD_SEVERITY_COLORS[severity])
		embed.set_description(message)
		embed.set_timestamp()
		existing_fields_dict = {field['name']: field['value'] for field in embed.fields}
		logger.debug(''.join([f'\n\t{k}: {v}' for k, v in fields.items()]))
		for name, value in fields.items():
			if not value: # cannot send empty field values to Discord [error 400]
				continue
			value = str(value)
			new_field = {'name': name, 'value': value, 'inline': False}

			# If field already existed in previous embed, update it.
			if name in existing_fields_dict.keys():
				field = [f for f in embed.fields if f['name'] == name][0]

				# Append to existing field value
				if name in fields_append:
					existing_val = field['value']
					existing_val = str(existing_val)
					if value not in existing_val:
						value = f'{existing_val}\n{value}'

					if len(value) > 1024: # character limit for embed field
						value = value[0:1016] + '\n[...]'

				# Update existing embed
				ix = embed.fields.index(field)
				embed.fields[ix]['value'] = value

			else:
				embed.add_embed_field(**new_field)

		webhook.add_embed(embed)

		# Add the embed to the cache, so we can pick it up later
		DISCORD_WEBHOOKS_CACHE.set(title + '_embed', _seal(embed))

	# Add files to webhook
	if files:
		for (path, name) in files:
			with open(path, 'r') as f:
				content = f.read()
			webhook.add_file(content, name)

	# Edit webhook if it already existed, otherwise send new webhook
	if cached_response:
		response = webhook.edit(cached_response)
	else:
		response = webhook.execute()
		if use_discord_embed and response.status_code == 200:
			DISCORD_WEBHOOKS_CACHE.set(title, _seal(response))

	# Get status code
	if response.status_code == 429 and _attempt < 2:  # rate limited: wait and retry, but only twice
		errors = json.loads(
			response.content.decode('utf-8'))
		wh_sleep = (int(errors['retry_after']) / 1000) + 0.15
		sleep(wh_sleep)
		send_discord_message(
				message,
				title,
				severity,
				url,
				files,
				fields,
				fields_append,
				_attempt + 1)
	elif response.status_code != 200:
		logger.error(
			f'Error while sending webhook data to Discord.'
			f'\n\tHTTP code: {response.status_code}.'
			f'\n\tDetails: {response.content}')


def enrich_notification(message, scan_history_id, subscan_id):
	"""Add scan id / subscan id to notification message.

	Args:
		message (str): Original notification message.
		scan_history_id (int): Scan history id.
		subscan_id (int): Subscan id.

	Returns:
		str: Message.
	"""
	if scan_history_id is not None:
		if subscan_id:
			message = f'`#{scan_history_id}_{subscan_id}`: {message}'
		else:
			message = f'`#{scan_history_id}`: {message}'
	return message


def get_scan_url(scan_id=None, subscan_id=None):
	"""Link to the scan's page in CVEngine, for notifications. Looked up unscoped: this runs in workers, not a request."""
	if scan_id:
		from startScan.models import ScanHistory
		slug = ScanHistory._base_manager.filter(pk=scan_id).values_list('domain__project__slug', flat=True).first()
		return f'https://{DOMAIN_NAME}/cve/{slug}/scans/{scan_id}/' if slug else f'https://{DOMAIN_NAME}/cve/'
	return None


def get_task_title(task_name, scan_id=None, subscan_id=None):
	if scan_id:
		prefix = f'#{scan_id}'
		if subscan_id:
			prefix += f'-#{subscan_id}'
		return f'`{prefix}` - `{task_name}`'
	return f'`{task_name}` [unbound]'


def get_task_cache_key(func_name, *args, **kwargs):
	args_str = '_'.join([str(arg) for arg in args])
	kwargs_str = '_'.join([f'{k}={v}' for k, v in kwargs.items() if k not in RENGINE_TASK_IGNORE_CACHE_KWARGS])
	return f'{func_name}__{args_str}__{kwargs_str}'


def get_output_file_name(scan_history_id, subscan_id, filename):
	title = f'#{scan_history_id}'
	if subscan_id:
		title += f'-{subscan_id}'
	title += f'_{filename}'
	return title


def get_traceback_path(task_name, results_dir, scan_history_id=None, subscan_id=None):
	path = results_dir
	if scan_history_id:
		path += f'/#{scan_history_id}'
		if subscan_id:
			path += f'-#{subscan_id}'
	path += f'-{task_name}.txt'
	return path


def fmt_traceback(exc):
	return '\n'.join(traceback.format_exception(None, exc, exc.__traceback__))


#--------------#
# CLI BUILDERS #
#--------------#


def get_port_service_description(port):
	"""
		Retrieves the standard service name and description for a given port 
		number using whatportis and the builtin socket library as fallback.

		Args:
			port (int or str): The port number to look up. 
				Can be an integer or a string representation of an integer.

		Returns:
			dict: A dictionary containing the service name and description for the port number.
	"""
	logger.info('Fetching Port Service Name and Description')
	try:
		port = int(port)
		whatportis_result = whatportis.get_ports(str(port))
		
		if whatportis_result and whatportis_result[0].name:
			return {
				"service_name": whatportis_result[0].name,
				"description": whatportis_result[0].description
			}
		else:
			try:
				service = socket.getservbyport(port)
				return {
					"service_name": service,
					"description": "" # Keep description blank when using socket
				}
			except OSError:
				# If both whatportis and socket fail
				return {
					"service_name": "",
					"description": ""
				}
	except:
		# port is not a valid int or any other exception
		return {
			"service_name": "",
			"description": ""
		}


def update_or_create_port(port_number, service_name=None, description=None, ip=None):
	"""
		Updates or creates a new Port object with the provided information to 
		avoid storing duplicate entries when service or description information is updated.

		Args:
			port_number (int): The port number to update or create.
			service_name (str, optional): The name of the service associated with the port.
			description (str, optional): A description of the service associated with the port.
			ip (IpAddress, optional): when given, the port is looked up among (and created for) this IP only, never
				shared with another IP: nmap's product and version are stored on the row, so a shared row would show
				one host's service on every host that has the same port number open.

		Returns:
			Tuple: A tuple containing the Port object and a boolean indicating whether the object was created.
	"""
	created = False
	# Several Port rows can share a number (service enrichment stores product and version per row), so
	# take the oldest instead of get(), which raised MultipleObjectsReturned and then hid it.
	if ip is not None:
		port = ip.ports.filter(number=port_number, protocol__in=('', 'tcp')).order_by('id').first()  # the callers (bbot, httpx) find TCP services
	else:
		port = Port.objects.filter(number=port_number).order_by('id').first()
	if port is None:
		port = Port.objects.create(
			number=port_number,
			service_name=service_name,
			description=description
		)
		created = True
	else:
		# avoid updating None values in service and description if they already exist
		if service_name is not None and port.service_name != service_name:
			port.service_name = service_name
		if description is not None and port.description != description:
			port.description = description
		port.save()
	return port, created
	

	

	


SCAN_RESULTS_ROOT = '/usr/src/scan_results'


def safe_remove_path(path, root=SCAN_RESULTS_ROOT):
	"""Delete ``path`` (file or directory tree) only if it lies strictly inside ``root``. Replaces ``rm -rf <value>``
	shell strings: no shell, so no argument or option injection (``x -rf /``), no globbing, and refusing ``root``
	itself and anything that resolves outside it (``..``, symlinks). Returns True if something was removed."""
	if not path:
		return False
	real, base = os.path.realpath(str(path)), os.path.realpath(root)
	if not real.startswith(base + os.sep):
		logger.warning('refusing to delete %r: not inside %s', path, root)
		return False
	if os.path.isdir(real):
		shutil.rmtree(real, ignore_errors=True)
	elif os.path.exists(real):
		os.remove(real)
	else:
		return False
	return True


