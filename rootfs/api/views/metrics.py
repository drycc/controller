"""
Metrics and proxy views.
"""
import asyncio
import json
import random
import re
import ssl
import time
import warnings
from collections import namedtuple
from urllib.parse import urljoin

import aiohttp
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.vary import vary_on_headers
from django.views.generic import View
from django.http.response import JsonResponse, StreamingHttpResponse
from channels.db import database_sync_to_async

from api import models, monitor
from api.views.app import AppFilterViewSet
from api.viewsets import BaseServiceView
from api import __version__


class MetricView(AppFilterViewSet):
    """Getting monitoring indicators from monitor database"""

    @method_decorator(cache_page(settings.DRYCC_METRICS_EXPIRY))
    @method_decorator(vary_on_headers("Authorization"))
    def metric(self, request, **kwargs):
        warnings.warn(
            'this interface will be removed in the next version.', PendingDeprecationWarning)
        app_id = self.get_app().id
        return StreamingHttpResponse(
            streaming_content=monitor.last_metrics(app_id)
        )


class MetricsProxyView(View):
    cache = {}
    cache_lock = asyncio.Lock()
    match_meta = staticmethod(
        re.compile(r'^(?:# (?:HELP|TYPE) )([a-zA-Z_][a-zA-Z0-9_:.-]*)').match)
    match_data = staticmethod(
        re.compile(r'^([a-zA-Z_][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+(\S+)').match)

    vm_tenant_cls = namedtuple('VMTenant', ['account_id', 'project_id'])
    default_cache_value = (None, -1)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if settings.K8S_API_VERIFY_TLS:
            ssl_context = ssl.create_default_context(
                cafile='/var/run/secrets/kubernetes.io/serviceaccount/ca.crt')
        else:
            ssl_context = ssl.create_default_context()
        self.connector = aiohttp.TCPConnector(ssl_context=ssl_context)

    async def sample(self, name, labels_str, value):
        if not labels_str or name not in settings.DRYCC_METRICS_CONFIG:
            return None
        fields = set(settings.DRYCC_METRICS_CONFIG[name])
        labels = {}
        for pair in labels_str.strip(" {}").split(','):
            if '=' not in pair:
                continue
            k, v = pair.split('=', 1)
            if k in fields:
                labels[k] = v.strip(' "')
        app_id = labels.get("namespace", labels.get(settings.DRYCC_METRICS_CONFIG[name][0]))
        if not app_id:
            return None
        async with self.cache_lock:
            tenant, timeout = self.cache.get(app_id, self.default_cache_value)
            if tenant is None or time.time() > timeout:
                app = await models.app.App.objects.select_related(
                    'workspace').filter(id=app_id).afirst()
                if app:
                    tenant = self.vm_tenant_cls(app.workspace.uid, app.uid)
                else:
                    tenant = None
                self.cache[app_id] = (
                    tenant, time.time() + random.randint(600, 1200))
        if tenant is None:
            return None
        labels.update({'vm_account_id': tenant.account_id, 'vm_project_id': tenant.project_id})
        return "%s{%s} %s\n" % (name, ",".join([f'{k}="{v}"' for k, v in labels.items()]), value)

    async def get(self, request):
        params = dict(request.GET)
        if not set(["host", "port"]).issubset(params.keys()):
            return HttpResponse(
                "Error: Required parameter 'host' or 'port' is missing or empty", status=400)
        host, port = params.pop('host')[0], params.pop('port')[0]
        scheme, path = params.pop('scheme', ['http'])[0], params.pop('path', ['/metrics'])[0]
        url = urljoin(f"{scheme}://{host}:{port}", path)
        headers = {"Authorization": request.META.get("HTTP_AUTHORIZATION", "")}

        async def stream_response():
            async with aiohttp.ClientSession(connector=self.connector) as session:
                async with session.get(url, params=params, headers=headers) as resp:
                    async for line_bytes in resp.content:
                        line = line_bytes.decode('utf-8', errors='ignore').strip(' \n')
                        if line.startswith('#') and (match := self.match_meta(line)):
                            if match.group(1) in settings.DRYCC_METRICS_CONFIG:
                                yield f"{line}\n"
                            continue
                        match = self.match_data(line)
                        if not match:
                            continue
                        name, labels_str, value = match.groups()
                        sample = await self.sample(name, labels_str, value)
                        if not sample:
                            continue
                        yield sample
        content_type = f"text/plain; version={__version__}"
        return StreamingHttpResponse(stream_response(), content_type=content_type)


@method_decorator(csrf_exempt, name='dispatch')
class QuickwitProxyView(BaseServiceView):
    timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=15)
    required_oauth_scopes = ['controller:logs']

    index_url_match = re.compile(r"^indexes/?$").match
    search_url_match = re.compile(r"^(?P<index>[a-zA-Z*][\w.*-，]{0,})/search/?$").match
    msearch_url_match = re.compile(r"^_elastic/_msearch/?$").match
    field_caps_url_match = re.compile(
        r"_elastic/(?P<index>[a-zA-Z*][\w.*-，]{0,})/_field_caps/?$").match

    async def proxy(self, request, workspace, path):
        kwargs = {"request": request, "workspace": workspace}
        if self.index_url_match(path):
            func, kwargs["index"] = self.index, request.GET.get("index_id_patterns", "*")
        elif match := self.search_url_match(path):
            func, kwargs["index"] = self.query, match.group("index")
        elif self.msearch_url_match(path):
            func = self.msearch
        elif match := self.field_caps_url_match(path):
            func, kwargs["index"] = self.field_caps, match.group("index")
        else:
            return JsonResponse({'error': 'Not Found'}, status=404)
        return await func(**kwargs)

    async def index(self, request, workspace, index):
        base_url = settings.QUICKWIT_SEARCHER_URL
        index = await self.get_app_indexes(workspace, index)
        url, params = urljoin(base_url, "/api/v1/indexes"), dict(request.GET)
        params["index_id_patterns"] = index
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=self.timeout) as response:
                    data, status = await response.json(), response.status
        except aiohttp.ClientError as e:
            data, status = {'error': f'quickwit connection failed: {str(e)}'}, 502
        return JsonResponse(data, status=status, safe=False)

    async def query(self, request, workspace, index):
        base_url = settings.QUICKWIT_SEARCHER_URL
        index = await self.get_app_indexes(workspace, index)
        url, params = urljoin(base_url, f"/api/v1/{index}/search"), dict(request.GET)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=self.timeout) as response:
                    data, status = await response.json(), response.status
        except aiohttp.ClientError as e:
            data, status = {'error': f'quickwit connection failed: {str(e)}'}, 502
        return JsonResponse(data, status=status)

    async def msearch(self, request, workspace):
        base_url = settings.QUICKWIT_SEARCHER_URL
        json_lines = request.body.decode('utf-8').strip().split('\n')
        for i, json_line in enumerate(json_lines):
            if i % 2 == 0:
                request_header = json.loads(json_line)
                request_header['index'] = ",".join(
                    [await self.get_app_indexes(workspace, i) for i in request_header['index']]
                ).split(",")
                json_lines[i] = json.dumps(request_header)
        url, params = urljoin(
            base_url, "/api/v1/_elastic/_msearch"), dict(request.GET)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, data="\n".join(json_lines), params=params, timeout=self.timeout
                ) as response:
                    data, status = await response.json(), response.status
        except aiohttp.ClientError as e:
            data, status = {'error': f'quickwit connection failed: {str(e)}'}, 502
        return JsonResponse(data, status=status)

    async def field_caps(self, request, workspace, index):
        base_url = settings.QUICKWIT_SEARCHER_URL
        index = await self.get_app_indexes(workspace, index)
        url, params = urljoin(
            base_url, f"/api/v1/_elastic/{index}/_field_caps"), dict(request.GET)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=self.timeout) as response:
                    data, status = await response.json(), response.status
        except aiohttp.ClientError as e:
            data, status = {'error': f'quickwit connection failed: {str(e)}'}, 502
        return JsonResponse(data, status=status)

    async def get_app_indexes(self, workspace, index):
        if workspace == "drycc":
            return index
        if "," in index:
            match = re.compile("|".join([f"^{i}$" for i in index.split(",")])).match
        else:
            match = re.compile(f"^{index}$").match
        log_index_prefix = settings.QUICKWIT_LOG_INDEX_PREFIX
        cache_key = f"quickwit:app_ids:{workspace}"
        app_ids = await cache.aget(cache_key)
        if app_ids is None:
            app_ids = [
                app.id async for app in models.app.App.objects.filter(
                    workspace__id=workspace).only('id').distinct()]
            await cache.aset(cache_key, app_ids, timeout=300)
        app_indexes = []
        for app_id in app_ids:
            app_index = f"{log_index_prefix}{app_id}"
            if match(app_index):
                app_indexes.append(app_index)
        return ",".join(app_indexes)

    get = post = proxy


@method_decorator(csrf_exempt, name='dispatch')
class PrometheusProxyView(BaseServiceView):
    timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=15)
    required_oauth_scopes = ['controller:metrics']

    async def proxy(self, request, workspace, path):
        data = dict(request.GET) if request.method == "GET" else dict(request.POST)
        if workspace == "drycc":
            workspace_uid = 0
        else:
            workspace_obj = await database_sync_to_async(get_object_or_404)(
                models.workspace.Workspace, id=workspace)
            workspace_uid = workspace_obj.uid
        data['extra_filters[]'] = '{vm_account_id="%s"}' % workspace_uid
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{settings.DRYCC_VICTORIAMETRICS_URL.rstrip("/")}/{path}",
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=self.timeout
                ) as response:
                    data, status = await response.json(), response.status
        except aiohttp.ClientError as e:
            data, status = {'error': f'victoriametrics connection failed: {str(e)}'}, 502
        return JsonResponse(data, status=status)

    get = post = proxy
