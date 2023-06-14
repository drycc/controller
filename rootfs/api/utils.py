"""
Helper functions used by the Drycc server.
"""
import os
import re
import base64
import string
import concurrent
import hashlib
import logging
import random
import math
import pkgutil
import inspect
import requests
from copy import deepcopy
from django.db import models
from requests_toolbelt import user_agent
from api import __version__ as drycc_version
from rest_framework.exceptions import ValidationError

logger = logging.getLogger(__name__)


session = None


def get_session():
    global session
    if session is None:
        session = requests.Session()
        session.headers = {
            # https://toolbelt.readthedocs.org/en/latest/user-agent.html#user-agent-constructor
            'User-Agent': user_agent('Drycc Controller', drycc_version),
        }
        # `mount` a custom adapter that retries failed connections for HTTP and HTTPS requests.
        # http://docs.python-requests.org/en/latest/api/#requests.adapters.HTTPAdapter
        session.mount('http://', requests.adapters.HTTPAdapter(max_retries=10))
        session.mount('https://', requests.adapters.HTTPAdapter(max_retries=10))
    return session


def import_all_models():
    for _, modname, ispkg in pkgutil.iter_modules([
        os.path.join(os.path.dirname(__file__), "models")
    ]):
        if not ispkg:
            mod = __import__(f"api.models.{modname}")
            for subname in dir(mod):
                attr = getattr(mod, subname)
                if inspect.isclass(attr) and issubclass(attr, models.Model):
                    globals()[subname] = attr


def validate_label(value):
    """
    Check that the value follows the kubernetes name constraints
    http://kubernetes.io/v1.1/docs/design/identifiers.html
    """
    match = re.match(r'^[a-z0-9-]+$', value)
    if not match:
        raise ValidationError("Can only contain a-z (lowercase), 0-9 and hyphens")


def random_string(num):
    return ''.join(
        [random.choice(string.ascii_lowercase) for i in range(num)])


def generate_app_name():
    """Return a randomly-generated memorable name."""
    return "{}-{}".format(random_string(6), random_string(8))


def dict_diff(dict1, dict2):
    """
    Returns the added, changed, and deleted items in dict1 compared with dict2.

    :param dict1: a python dict
    :param dict2: an earlier version of the same python dict
    :return: a new dict, with 'added', 'changed', and 'removed' items if
             any were found.

    >>> d1 = {1: 'a'}
    >>> dict_diff(d1, d1)
    {}
    >>> d2 = {1: 'a', 2: 'b'}
    >>> dict_diff(d2, d1)
    {'added': {2: 'b'}}
    >>> d3 = {2: 'B', 3: 'c'}
    >>> expected = {'added': {3: 'c'}, 'changed': {2: 'B'}, 'deleted': {1: 'a'}}
    >>> dict_diff(d3, d2) == expected
    True
    """
    diff = {}
    set1, set2 = set(dict1), set(dict2)
    # Find items that were added to dict2
    diff['added'] = {k: dict1[k] for k in (set1 - set2)}
    # Find common items whose values differ between dict1 and dict2
    diff['changed'] = {
        k: dict1[k] for k in (set1 & set2) if dict1[k] != dict2[k]
    }
    # Find items that were deleted from dict2
    diff['deleted'] = {k: dict2[k] for k in (set2 - set1)}
    return {k: diff[k] for k in diff if diff[k]}


def fingerprint(key):
    """
    Return the fingerprint for an SSH Public Key
    """
    key = base64.b64decode(key.strip().split()[1].encode('ascii'))
    fp_plain = hashlib.md5(key).hexdigest()
    return ':'.join(a + b for a, b in zip(fp_plain[::2], fp_plain[1::2]))


def dict_merge(origin, merge):
    """
    Recursively merges dict's. not just simple a["key"] = b["key"], if
    both a and b have a key who's value is a dict then dict_merge is called
    on both values and the result stored in the returned dictionary.
    Also handles merging lists if they occur within the dict
    """
    if not isinstance(merge, dict):
        return merge

    result = deepcopy(origin)
    for key, value in merge.items():
        if key in result and isinstance(result[key], dict):
            result[key] = dict_merge(result[key], value)
        else:
            if isinstance(value, list):
                if key not in result:
                    result[key] = value
                else:
                    # merge lists without leaving potential duplicates
                    # result[key] = list(set(result[key] + value))  # changes the order as well
                    for item in value:
                        if item in result[key]:
                            continue

                        result[key].append(item)
            else:
                result[key] = deepcopy(value)
    return result


def apply_tasks(tasks):
    """
    run a group of tasks async
    Requires the tasks arg to be a list of functools.partial()
    """
    if not tasks:
        return

    executor = concurrent.futures.ThreadPoolExecutor(5)
    for future in [executor.submit(task) for task in tasks]:
        error = future.exception()
        if error is not None:
            raise error
    executor.shutdown(wait=True)


def unit_to_bytes(size):
    """
    size: str
    where unit in K, M, G, T convert to B
    """
    if size[-2:-1].isalpha() and size[-1].isalpha():
        size = size[:-1]
    if size[-1].isalpha():
        size = size.upper()
    _ = float(size[:-1])
    if size[-1] == 'K':
        _ *= math.pow(1024, 1)
    elif size[-1] == 'M':
        _ *= math.pow(1024, 2)
    elif size[-1] == 'G':
        _ *= math.pow(1024, 3)
    elif size[-1] == 'G':
        _ *= math.pow(1024, 3)
    elif size[-1] == 'T':
        _ *= math.pow(1024, 4)
    elif size[-1] == 'P':
        _ *= math.pow(1024, 5)
    return round(_)


def unit_to_millicpu(cpu):
    cpu = cpu.lower()
    if cpu.endswith("m") and cpu[:-1].isdigit():
        return int(cpu[:-1])
    elif cpu.isdigit():
        return int(cpu) * 1000
    else:
        raise ValueError("Unrecognized CPU unit: %s" % cpu)


if __name__ == "__main__":
    import doctest
    doctest.testmod()
