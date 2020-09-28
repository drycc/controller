import os
import json
import logging
import asyncio
import concurrent
import nsq
from functools import wraps, partial

logger = logging.getLogger(__name__)


def _message_handler(message):

    async def _async_task(loop):
        data = json.loads(message.body)
        function = TASKS[data["target_id"]]
        _sync_task = partial(function, *data["args"], **data["kwargs"])
        with concurrent.futures.ThreadPoolExecutor() as executor:
            await loop.run_in_executor(executor, _sync_task)
            message.finish()

    message.enable_async()
    asyncio.set_event_loop(asyncio.new_event_loop())
    asyncio.ensure_future(_async_task(asyncio.get_event_loop()))


TASKS = {}
NSQD_ADDRS = os.environ.get('DRYCC_NSQD_ADDRS', '127.0.0.1:4150').split(",")
NSQ_TOPIC = os.environ.get('DRYCC_NSQ_TASKS_TOPIC', 'drycc-tasks-topic')
NSQ_CHANNEL = os.environ.get('DRYCC_NSQ_TASKS_CHANNEL', 'drycc-tasks-channel')
NSQD_WRITER = nsq.Writer(NSQD_ADDRS)
NSQD_READER = nsq.Reader(
    message_handler=_message_handler,
    nsqd_tcp_addresses=NSQD_ADDRS,
    topic=NSQ_TOPIC,
    channel=NSQ_CHANNEL,
    lookupd_poll_interval=15,
)


def task(func):
    target_id = "%s.%s" % (func.__module__, func.__name__)
    TASKS[target_id] = func

    @wraps(func)
    def register_task(*args, **kwargs):
        return func(*args, **kwargs)

    return register_task


def apply_async(target, delay=0, callback=None, args=(), kwargs=None):
    target_id = "%s.%s" % (target.__module__, target.__name__)
    if target_id not in TASKS:
        raise NotImplementedError("This task is not registered.")
    message = json.dumps({
        "target_id": target_id,
        "args": args,
        "kwargs": {} if kwargs is None else kwargs
    }).encode("utf-8")

    asyncio.set_event_loop(asyncio.new_event_loop())
    if delay <= 0:
        NSQD_WRITER.pub(NSQ_TOPIC, message, callback=callback)
    else:
        NSQD_WRITER.dpub(NSQ_TOPIC, delay, message, callback=callback)
