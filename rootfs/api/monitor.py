import time
import aiohttp
from typing import Iterator, AsyncGenerator
from urllib.parse import urljoin
from django.conf import settings


query_last_metrics_promql_tpl = """
last_over_time({__name__=~"%s",namespace="%s"}[%s])
"""

query_network_receive_flow_promql_tpl = """
increase(container_network_receive_bytes_total{namespace=~"%s"}[%s])
"""

query_network_transmit_flow_promql_tpl = """
increase(container_network_transmit_bytes_total{namespace=~"%s"}[%s])
"""

query_cpu_usage_promql_tpl = """
sum (rate (container_cpu_usage_seconds_total{pod=~"^%s-.*$",namespace="%s"}[%s]))
by (pod)
"""


query_memory_usage_promql_tpl = """
sum (avg_over_time (container_memory_working_set_bytes{pod=~"^%s-.*$",namespace="%s"}[%s]))
by (pod)
"""


query_network_receive_usage_promql_tpl = """
sum (rate (container_network_receive_bytes_total{pod=~"^%s-.*$",namespace="%s"}[%s]))
by (pod)
"""

query_network_transmit_usage_promql_tpl = """
sum (rate (container_network_transmit_bytes_total{pod=~"^%s-.*$",namespace="%s"}[%s]))
by (pod)
"""


async def query_prom(url, params) -> list[tuple[dict[str, str], int]]:
    async with aiohttp.ClientSession() as session:
        async with session.get(url, params=params) as response:
            if response.status != 200:
                return []
            response_json = await response.json()
            if response_json['status'] != 'success':
                return []
            return response_json['data']['result']


async def last_metrics(namespace) -> AsyncGenerator[Iterator, str]:
    if not settings.DRYCC_METRICS_CONFIG:
        return
    url = urljoin(settings.DRYCC_VICTORIAMETRICS_URL, "/select/0/prometheus/api/v1/query")
    promql = query_last_metrics_promql_tpl % (
      '|'.join(settings.DRYCC_METRICS_CONFIG.keys()),
      namespace,
      settings.DRYCC_METRICS_INTERVAL)
    for item in await query_prom(url, {"query": promql, "start": int(time.time() - 60)}):
        yield '%s{%s} %s\n' % (
            item['metric']['__name__'],
            ','.join([
                f'{key}="{value}"' for key, value in item['metric'].items()
                if key in settings.DRYCC_METRICS_CONFIG[item['metric']['__name__']]
            ]),
            item['value'][1]
        )


async def query_network_receive_flow(namespaces: Iterator[str], start: int, stop: int
                                     ) -> list[tuple[dict[str, str], int]]:
    url = urljoin(settings.DRYCC_VICTORIAMETRICS_URL, "/select/0/prometheus/api/v1/query")
    promql = query_network_receive_flow_promql_tpl % ("|".join(namespaces), f"{stop-start}s")
    return await query_prom(url, {"query": promql, "start": start, "end": stop})


async def query_network_transmit_flow(namespaces: Iterator[str], start: int, stop: int
                                      ) -> list[tuple[dict[str, str], int]]:
    url = urljoin(settings.DRYCC_VICTORIAMETRICS_URL, "/select/0/prometheus/api/v1/query")
    promql = query_network_transmit_flow_promql_tpl % ("|".join(namespaces), f"{stop-start}s")
    return await query_prom(url, {"query": promql, "start": start, "end": stop})


async def query_cpu_usage(namespace: str, ptype: str, every: str,
                          start: int, stop: int, step: int,
                          ) -> list[tuple[dict[str, str], int]]:
    url = urljoin(settings.DRYCC_VICTORIAMETRICS_URL, "/select/0/prometheus/api/v1/query_range")
    pod_prefix = "%s-%s" % (namespace, ptype)
    promql = query_cpu_usage_promql_tpl % (pod_prefix, namespace, every)
    return await query_prom(url, {"query": promql, "start": start, "end": stop, "step": step})


async def query_memory_usage(namespace: str, ptype: str, every: str,
                             start: int, stop: int, step: int,
                             ) -> list[tuple[dict[str, str], int]]:
    url = urljoin(settings.DRYCC_VICTORIAMETRICS_URL, "/select/0/prometheus/api/v1/query_range")
    pod_prefix = "%s-%s" % (namespace, ptype)
    promql = query_memory_usage_promql_tpl % (pod_prefix, namespace, every)
    return await query_prom(url, {"query": promql, "start": start, "end": stop, "step": step})


async def query_network_receive_usage(namespace: str, ptype: str, every: str,
                                      start: int, stop: int, step: int,
                                      ) -> list[tuple[dict[str, str], int]]:
    url = urljoin(settings.DRYCC_VICTORIAMETRICS_URL, "/select/0/prometheus/api/v1/query_range")
    pod_prefix = "%s-%s" % (namespace, ptype)
    promql = query_network_receive_usage_promql_tpl % (pod_prefix, namespace, every)
    return await query_prom(url, {"query": promql, "start": start, "end": stop, "step": step})


async def query_network_transmit_usage(namespace: str, ptype: str, every: str,
                                       start: int, stop: int, step: int,
                                       ) -> list[tuple[dict[str, str], int]]:
    url = urljoin(settings.DRYCC_VICTORIAMETRICS_URL, "/select/0/prometheus/api/v1/query_range")
    pod_prefix = "%s-%s" % (namespace, ptype)
    promql = query_network_transmit_usage_promql_tpl % (pod_prefix, namespace, every)
    return await query_prom(url, {"query": promql, "start": start, "end": stop, "step": step})
