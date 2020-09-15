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
        def t1(name, value, t):
            self.assertEqual(name == "hi", True)
            self.assertEqual(value == "word", True)

        @task
        def t2(t):
            self.assertEqual(time.time() - t > 3, True)

        def callback(_, msg):
            self.assertEqual(msg == b'OK', True)

        loop = tornado.ioloop.IOLoop.current()
        threading.Thread(target=loop.start).start()
        time.sleep(9)
        apply_async(t1, callback=callback, args=("hi", "word", time.time()))
        apply_async(t2, callback=callback, delay=3000, args=(time.time(), ))
        time.sleep(9)
        loop.stop()
