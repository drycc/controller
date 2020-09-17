import unittest
import time
import datetime
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
            self.assertEqual(name == "hi", True)
            self.assertEqual(value == "word", True)

        @task
        def t2(t):
            self.assertEqual(time.time() - t > 3, True)

        def callback(_, msg):
            self.assertEqual(msg == b'OK', True)

        def run_test_task():
            loop = tornado.ioloop.IOLoop.current()
            try:
                apply_async(t1, callback=callback, args=("hi", "word"))
                apply_async(t2, callback=callback, delay=3000, args=(time.time(),))
            finally:
                _loop.add_timeout(datetime.timedelta(seconds=9), loop.stop)

        _loop = tornado.ioloop.IOLoop.current()
        _loop.add_timeout(datetime.timedelta(seconds=3), run_test_task)
        _loop.start()
