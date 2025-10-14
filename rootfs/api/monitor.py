import time
import aiohttp
from string import Template
from typing import Iterator, AsyncGenerator
from django.conf import settings


query_last_metrics_promql_tpl = Template("""
last_over_time({__name__=~"${metrics}",namespace="${namespace}"}[${duration}])
""")


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
    url = f"{settings.DRYCC_VICTORIAMETRICS_URL}/api/v1/query"
    promql = query_last_metrics_promql_tpl.substitute(
        metrics='|'.join(settings.DRYCC_METRICS_CONFIG.keys()),
        namespace=namespace,
        duration=settings.DRYCC_METRICS_INTERVAL
    )
    for item in await query_prom(url, {"query": promql, "start": int(time.time() - 60)}):
        yield '%s{%s} %s\n' % (
            item['metric']['__name__'],
            ','.join([
                f'{key}="{value}"' for key, value in item['metric'].items()
                if key in settings.DRYCC_METRICS_CONFIG[item['metric']['__name__']]
            ]),
            item['value'][1]
        )


async def query_volume_usage(namespaces: Iterator[str], start: int, stop: int
                             ) -> list[tuple[dict[str, str], int]]:
    if not settings.DRYCC_VICTORIAMETRICS_URL:
        return []
    url = f"{settings.DRYCC_VICTORIAMETRICS_URL}/api/v1/query"
    promql = Template(settings.DRYCC_VOLUME_USAGE_TEMPLATE).substitute(
        namespaces="|".join(namespaces)
    )
    return await query_prom(url, {"query": promql, "start": start, "end": stop})


async def query_network_usage(namespaces: Iterator[str], start: int, stop: int
                              ) -> list[tuple[dict[str, str], int]]:
    url = f"{settings.DRYCC_VICTORIAMETRICS_URL}/api/v1/query"
    promql = Template(settings.DRYCC_NETWORK_USAGE_TEMPLATE).substitute(
        namespaces="|".join(namespaces),
        duration=f"{stop-start}s"
    )
    return await query_prom(url, {"query": promql, "start": start, "end": stop})
