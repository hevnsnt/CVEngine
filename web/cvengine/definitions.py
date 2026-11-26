"""Shared constants for CVEngine.

Many modules import everything from here with a star import, so no __all__ is defined.
Several values are stored in the database, so they must not change.
"""

import logging

logger = logging.getLogger('django')

# Engine YAML keys
ALL = 'all'
EXTENSIONS = 'extensions'
OSINT = 'osint'
PORT = 'port'
RATE_LIMIT = 'rate_limit'
RETRIES = 'retries'
TIMEOUT = 'timeout'
NUCLEI = 'nuclei'
NMAP = 'nmap'
USER_AGENT = 'user_agent'
PROVIDERS = 'providers'

# Nuclei severities
NUCLEI_SEVERITY_MAP = {
    'info': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
    'unknown': -1,
}
NUCLEI_REVERSE_SEVERITY_MAP = {value: key for key, value in NUCLEI_SEVERITY_MAP.items()}

# Discord colours
DISCORD_INFO_COLOR = '0xfbbc00'
DISCORD_WARNING_COLOR = '0xf75b00'
DISCORD_ERROR_COLOR = '0xf70000'
DISCORD_SUCCESS_COLOR = '0x00ff78'
DISCORD_SEVERITY_COLORS = {
    'info': DISCORD_INFO_COLOR,
    'warning': DISCORD_WARNING_COLOR,
    'error': DISCORD_ERROR_COLOR,
    'aborted': DISCORD_ERROR_COLOR,
    'success': DISCORD_SUCCESS_COLOR,
}
STATUS_TO_SEVERITIES = {
    'RUNNING': 'info',
    'SUCCESS': 'success',
    'FAILED': 'error',
    'ABORTED': 'error',
}

# Task status codes
INITIATED_TASK = -1
FAILED_TASK = 0
RUNNING_TASK = 1
SUCCESS_TASK = 2
ABORTED_TASK = 3
CELERY_TASK_STATUS_MAP = {
    INITIATED_TASK: 'INITITATED',
    FAILED_TASK: 'FAILED',
    RUNNING_TASK: 'RUNNING',
    SUCCESS_TASK: 'SUCCESS',
    ABORTED_TASK: 'ABORTED',
}
CELERY_TASK_STATUSES = (
    (-1, -1),
    (0, 0),
    (1, 1),
    (2, 2),
    (3, 3),
)

# Permission names
PERM_MODIFY_SYSTEM_CONFIGURATIONS = 'modify_system_configurations'
PERM_MODIFY_SCAN_CONFIGURATIONS = 'modify_scan_configurations'
PERM_MODIFY_TARGETS = 'modify_targets'
PERM_MODIFY_SCAN_RESULTS = 'modify_scan_results'
PERM_MODIFY_WORDLISTS = 'modify_wordlists'
PERM_MODIFY_INTERESTING_LOOKUP = 'modify_interesting_lookup'
PERM_MODIFY_SCAN_REPORT = 'modify_scan_report'
PERM_INITATE_SCANS_SUBSCANS = 'initiate_scans_subscans'

# Redirect targets
FOUR_OH_FOUR_URL = '/404/'

# Notifications
SYSTEM_LEVEL_NOTIFICATION = 'system'
PROJECT_LEVEL_NOTIFICATION = 'project'
NOTIFICATION_TYPES = (
    ('system', 'system'),
    ('project', 'project'),
)
NOTIFICATION_STATUS_TYPES = (
    ('success', 'Success'),
    ('info', 'Informational'),
    ('warning', 'Warning'),
    ('error', 'Error'),
)
