import unittest
import time
import threading
import tornado.ioloop
from tasks.task import TASKS
from tasks import task, apply_async


class TestUtils(unittest.TestCase):

    def test_task(self):
        @task
        def t():
            pass
        target_id = "%s.%s" % (t.__module__, t.__name__)
        self.assertEqual(target_id in TASKS, True)

    def test_apply_async(self):

        @task
        def t1(name, value):
            self.assertEqual(name == "hello", True)
            self.assertEqual(value == "word", True)

        @task
        def t2(t):
            self.assertEqual(time.time() - t > 3, True)

        def callback(addr, msg):
            self.assertEqual(msg == b'OK', True)

        threading.Thread(
            target=tornado.ioloop.IOLoop.current().start).start()
        time.sleep(3)
        apply_async(t1, callback=callback, args=("hello", "word"))
        apply_async(t2, callback=callback, delay=3000, args=(time.time(), ))
        time.sleep(12)
        tornado.ioloop.IOLoop.current().stop()
