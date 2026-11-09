"""``@legacy_snapshots`` runs a test class with the per-project dashboard snapshots switched off (``CVENGINE_DASHBOARD_SNAPSHOTS=0``), which is the
behaviour the per-scope cache tests describe: the kill switch keeps that path alive and tested."""
import os
from unittest import mock


def legacy_snapshots(cls):
    original = getattr(cls, 'setUp', None)
    if original is None:  # a mixin: the test classes that use it are decorated themselves
        return cls

    def setUp(self):
        patcher = mock.patch.dict(os.environ, {'CVENGINE_DASHBOARD_SNAPSHOTS': '0'})
        patcher.start()
        self.addCleanup(patcher.stop)
        original(self)
    cls.setUp = setUp
    return cls


def prime():
    """Compute every project's dashboard snapshot now: the numbers the dashboard reads are stored ones, and a test that changed data reads them after this."""
    from cveFeed import dashboard_snapshot
    from django.core.cache import cache
    cache.delete_many([dashboard_snapshot.key_of(pid) for pid in dashboard_snapshot.visible_ids_all()])
    return dashboard_snapshot.refresh_all()
