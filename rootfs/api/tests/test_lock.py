import time
from api.tests import DryccTestCase
from api.utils import CacheLock, DeployLock


class TestLock(DryccTestCase):

    def test_cache_lock(self):
        key = f"test_key_1_{int(time.time())}"
        lock1 = CacheLock(key)
        lock2 = CacheLock(key)
        timeout = 5
        self.assertEqual(lock1.acquire(True, timeout), True)
        self.assertEqual(lock2.acquire(False, timeout), False)
        time.sleep(5)
        start_time = time.time()
        self.assertEqual(lock2.acquire(False, timeout), True)
        self.assertEqual(lock1.acquire(True, timeout + 1), True)
        self.assertTrue(time.time()-start_time > 5)
        self.assertEqual(lock2.acquire(False, timeout), False)
        lock1.release()
        self.assertEqual(lock2.acquire(False, timeout), True)

    def test_deploy_lock(self):
        app_id = f"test_key_1_{int(time.time())}"
        lock1 = DeployLock(app_id)
        lock2 = DeployLock(app_id)
        self.assertEqual(lock1.acquire(None), True)
        self.assertEqual(lock2.acquire(["web", "task"]), False)
        lock1.release(None)
        self.assertEqual(lock2.acquire(["web", "task"]), True)
        self.assertEqual(lock1.acquire(None), False)
        self.assertEqual(lock1.acquire(["web"]), False)
        self.assertEqual(lock1.acquire(["bing"]), True)
        lock2.release(["web", "task"])
        self.assertEqual(lock1.acquire(["web"]), True)
        self.assertEqual(lock1.acquire(["task"]), True)
        self.assertEqual(lock2.acquire(["web", "task"]), False)
        self.assertEqual(lock2.acquire(None), False)
        lock2.release(["web", "task", "bing"])
        self.assertEqual(lock2.acquire(None), True)
        lock2.release(None)
        self.assertEqual(lock1.acquire(["web", "task"]), True)
        self.assertEqual(lock2.acquire(["web", "task"]), False)
        self.assertEqual(lock2.acquire(["web", "bing"], True), True)
        self.assertEqual(lock1.acquire(["web", "bing", "task"]), False)
        self.assertEqual(lock1.acquire(["web", "bing", "task"], True), True)
        lock2.release(["web", "bing", "task"])
