#!/usr/bin/python
import logging
import os
import re

###############################################################################
# TOOLS DEFINITIONS
###############################################################################
logger = logging.getLogger('django')

###############################################################################
# YAML CONFIG DEFINITIONS
###############################################################################

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

###############################################################################
# Tools DEFAULTS
###############################################################################


NUCLEI_SEVERITY_MAP = {
    'info': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
    'unknown': -1,
}
NUCLEI_REVERSE_SEVERITY_MAP = {v: k for k, v in NUCLEI_SEVERITY_MAP.items()}


###############################################################################
# Preferences DEFINITIONS
###############################################################################


# Discord message colors
DISCORD_INFO_COLOR = '0xfbbc00' # yellow
DISCORD_WARNING_COLOR = '0xf75b00' # orange
DISCORD_ERROR_COLOR = '0xf70000'
DISCORD_SUCCESS_COLOR = '0x00ff78'
DISCORD_SEVERITY_COLORS = {
    'info': DISCORD_INFO_COLOR,
    'warning': DISCORD_WARNING_COLOR,
    'error': DISCORD_ERROR_COLOR,
    'aborted': DISCORD_ERROR_COLOR,
    'success': DISCORD_SUCCESS_COLOR
}

STATUS_TO_SEVERITIES = {
    'RUNNING': 'info',
    'SUCCESS': 'success',
    'FAILED': 'error',
    'ABORTED': 'error'
}


###############################################################################
# Celery Task Status CODES
###############################################################################
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
    ABORTED_TASK: 'ABORTED'
}

CELERY_TASK_STATUSES = (
    (INITIATED_TASK, INITIATED_TASK),
    (FAILED_TASK, FAILED_TASK),
    (RUNNING_TASK, RUNNING_TASK),
    (SUCCESS_TASK, SUCCESS_TASK),
    (ABORTED_TASK, ABORTED_TASK)
)


############################################################################ Roles and Permissions
PERM_MODIFY_SYSTEM_CONFIGURATIONS = 'modify_system_configurations'
PERM_MODIFY_SCAN_CONFIGURATIONS = 'modify_scan_configurations'
PERM_MODIFY_TARGETS = 'modify_targets' # projects and targets
PERM_MODIFY_SCAN_RESULTS = 'modify_scan_results'
PERM_MODIFY_WORDLISTS = 'modify_wordlists'
PERM_MODIFY_INTERESTING_LOOKUP = 'modify_interesting_lookup'
PERM_MODIFY_SCAN_REPORT = 'modify_scan_report'
PERM_INITATE_SCANS_SUBSCANS = 'initiate_scans_subscans'

# 404 page url
FOUR_OH_FOUR_URL = '/404/'


# In App Notification Definitions
SYSTEM_LEVEL_NOTIFICATION = 'system'
PROJECT_LEVEL_NOTIFICATION = 'project'
NOTIFICATION_TYPES = (
    ('system', SYSTEM_LEVEL_NOTIFICATION),
    ('project', PROJECT_LEVEL_NOTIFICATION),
)
NOTIFICATION_STATUS_TYPES = (
    ('success', 'Success'),
    ('info', 'Informational'),
    ('warning', 'Warning'),
    ('error', 'Error'),
)

