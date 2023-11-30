import requests
from typing import Iterator, Dict
from contextlib import closing
from django.db import connections
from django.conf import settings


query_network_flow_sql_tpl = """
SELECT
  namespace,
  pod_name,
  last(rx_bytes, time) - first(rx_bytes, time) as rx_bytes,
  last(tx_bytes, time) - first(tx_bytes, time) as tx_bytes
FROM kubernetes_pod_network
LEFT OUTER JOIN kubernetes_pod_network_tag
ON kubernetes_pod_network.tag_id = kubernetes_pod_network_tag.tag_id
WHERE
  namespace in ({namespace_range})
  AND time > to_timestamp({start})
  AND time < to_timestamp({stop})
GROUP by namespace, pod_name
"""


query_container_count_sql_tpl = """
SELECT
  count(1)
FROM (
  SELECT
    namespace,
    pod_name,
    container_name
  FROM kubernetes_pod_container
  LEFT OUTER JOIN kubernetes_pod_container_tag
  ON kubernetes_pod_container.tag_id = kubernetes_pod_container_tag.tag_id
  WHERE
    namespace='{namespace}'
    AND container_name='{container_name}'
    AND time > to_timestamp({start})
    AND time < to_timestamp({stop})
  GROUP BY namespace, pod_name, container_name, kubernetes_pod_container.tag_id
) AS container
GROUP BY namespace, container_name
"""


query_cpu_usage_sql_tpl = """
SELECT
  namespace,
  pod_name,
  container_name,
  round(EXTRACT(EPOCH FROM time_bucket('{every}', time))) as timestamp,
  max(cpu_usage_nanocores),
  round(avg(cpu_usage_nanocores))
FROM kubernetes_pod_container
LEFT OUTER JOIN kubernetes_pod_container_tag
ON kubernetes_pod_container.tag_id = kubernetes_pod_container_tag.tag_id
WHERE
  namespace='{namespace}'
  AND container_name='{container_name}'
  AND time > to_timestamp({start})
  AND time < to_timestamp({stop})
GROUP BY namespace, pod_name, container_name, timestamp
"""


query_memory_usage_sql_tpl = """
SELECT
  namespace,
  pod_name,
  container_name,
  round(EXTRACT(EPOCH FROM time_bucket('{every}', time))) as timestamp,
  max(memory_usage_bytes) as max,
  round(avg(memory_usage_bytes)) as avg
FROM kubernetes_pod_container
LEFT OUTER JOIN kubernetes_pod_container_tag
ON kubernetes_pod_container.tag_id = kubernetes_pod_container_tag.tag_id
WHERE
  namespace='{namespace}'
  AND container_name='{container_name}'
  AND time > to_timestamp({start})
  AND time < to_timestamp({stop})
GROUP BY namespace, pod_name, container_name, timestamp
"""


query_network_usage_sql_tpl = """
SELECT
  namespace,
  pod_name,
  round(EXTRACT(EPOCH FROM time_bucket('{every}', time))) as timestamp,
  last(rx_bytes, time) - first(rx_bytes, time) as rx_bytes,
  last(tx_bytes, time) - first(tx_bytes, time) as tx_bytes
FROM kubernetes_pod_network
LEFT OUTER JOIN kubernetes_pod_network_tag
ON kubernetes_pod_network.tag_id = kubernetes_pod_network_tag.tag_id
WHERE
  namespace='{namespace}'
  AND pod_name like '{pod_name_prefix}%'
  AND time > to_timestamp({start})
  AND time < to_timestamp({stop})
GROUP by namespace, pod_name, timestamp
"""


query_loadbalancer_promql_tpl = """
max_over_time(kube_service_status_load_balancer_ingress{namespace=~"%s"}[60m])
"""


def query_loadbalancer(namespaces: Iterator[str],
                        start: int, stop: int) -> Iterator[Dict[str, str]]:
    promql = query_loadbalancer_promql_tpl % "|".join(namespaces)
    params = {"query": promql, "start": start, "end": stop}
    response = requests.get(settings.DRYCC_PROMETHEUS_URL, params=params)
    if response.status_code != 200:
        return StopIteration
    yield from (metric["metric"] for metric in response.json()["data"]["result"])


def query_network_flow(namespaces: Iterator[str],
                       start: int, stop: int) -> Iterator[tuple[str, str, int, int]]:
    with closing(connections['monitor'].cursor()) as cursor:
        namespace_range = ', '.join([f"'{namespace}'" for namespace in namespaces])
        sql = query_network_flow_sql_tpl.format(
            namespace_range=namespace_range, start=start, stop=stop)
        cursor.execute(sql)
        yield from cursor


def query_container_count(namespace: str, container_type: str, start: int, stop: int) -> int:
    with closing(connections['monitor'].cursor()) as cursor:
        container_name = "%s-%s" % (namespace, container_type)
        sql = query_container_count_sql_tpl.format(
            namespace=namespace, container_name=container_name, start=start, stop=stop)
        cursor.execute(sql)
        row = cursor.fetchone()
        return row[0] if row else 0


def query_cpu_usage(namespace: str, container_type: str,
                    start: int, stop: int, every: str
                    ) -> Iterator[tuple[str, str, str, int, int, int]]:
    with closing(connections['monitor'].cursor()) as cursor:
        container_name = "%s-%s" % (namespace, container_type)
        sql = query_cpu_usage_sql_tpl.format(
            namespace=namespace, container_name=container_name,
            start=start, stop=stop, every=every)
        cursor.execute(sql)
        yield from cursor


def query_memory_usage(namespace: str, container_type: str,
                       start: int, stop: int, every: str
                       ) -> Iterator[tuple[str, str, str, int, int, int]]:
    with closing(connections['monitor'].cursor()) as cursor:
        container_name = "%s-%s" % (namespace, container_type)
        sql = query_memory_usage_sql_tpl.format(
            namespace=namespace, container_name=container_name,
            start=start, stop=stop, every=every)
        cursor.execute(sql)
        yield from cursor


def query_network_usage(namespace: str, container_type: str,
                        start: int, stop: int, every: str
                        ) -> Iterator[tuple[str, str, int, int, int]]:
    with closing(connections['monitor'].cursor()) as cursor:
        pod_name_prefix = "%s-%s" % (namespace, container_type)
        sql = query_network_usage_sql_tpl.format(
            namespace=namespace, pod_name_prefix=pod_name_prefix,
            start=start, stop=stop, every=every)
        cursor.execute(sql)
        yield from cursor
