import threading
import logging
from typing import Iterator
from contextlib import closing
from django.conf import settings
from influxdb_client import InfluxDBClient
from influxdb_client.client.flux_table import FluxRecord
from influxdb_client.rest import ApiException

local = threading.local()
logger = logging.getLogger(__name__)


def _get_influxdb_client() -> InfluxDBClient:
    if not hasattr(local, "influxdb_client"):
        local.influxdb_client = InfluxDBClient(
            url=settings.DRYCC_INFLUXDB_URL,
            token=settings.DRYCC_INFLUXDB_TOKEN,
            org=settings.DRYCC_INFLUXDB_ORG
        )
    return local.influxdb_client


def _query_stream(flux_script: str) -> Iterator[FluxRecord]:
    with closing(_get_influxdb_client()) as client:
        try:
            query_api = client.query_api()
            records = query_api.query_stream(flux_script)
        except ApiException as e:
            logger.exception(e)
            yield from []
        except Exception as e:
            logger.exception(e)
            yield from []
        else:
            yield from records


def query_container_count(
        namespaces: Iterator[str], start: int, stop: int) -> Iterator[FluxRecord]:
    namespace_range = ' or '.join(
        ['r["namespace"] == \"{namespace}\"' for namespace in namespaces])
    flux_script = f'''
        from(bucket: "kubernetes")
            |> range(start: {start}, stop: {stop})
            |> filter(fn: (r) => r["_measurement"] == "kubernetes_pod_container")
            |> filter(fn: (r) => r["_field"]=="cpu_usage_core_nanoseconds")
            |> filter(fn: (r) => {namespace_range})
            |> group(columns: ["_time", "namespace", "container_name"])
            |> count()
            |> group(columns: ["namespace", "container_name"])
            |> top(n: 3)
            |> min()
    '''
    yield from _query_stream(flux_script)


def query_network_flow(
        namespaces: Iterator[str], start: int, stop: int) -> Iterator[FluxRecord]:
    namespace_range = ' or '.join(
        ['r["namespace"] == \"{namespace}\"' for namespace in namespaces])
    flux_script = f'''
        from(bucket: "kubernetes")
            |> range(start: {start}, stop: {stop})
            |> filter(fn: (r) => r["_measurement"] == "kubernetes_pod_network")
            |> filter(fn: (r) => r["_field"] == "rx_bytes" or r["_field"] == "tx_bytes")
            |> filter(fn: (r) => {namespace_range})
            |> increase()
            |> last()
            |> pivot(
                rowKey:["_time"],
                columnKey: ["_field"],
                valueColumn: "_value"
            )
    '''
    yield from _query_stream(flux_script)


def query_cpu_usage(
        namespace, container_type, start, stop, every) -> Iterator[FluxRecord]:
    flux_script = f"""
        from(bucket: "kubernetes")
            |> range(start: {start}, stop: {stop})
            |> filter(fn: (r) => r["_measurement"] == "kubernetes_pod_container")
            |> filter(fn: (r) => r["_field"] == "cpu_usage_nanocores")
            |> filter(fn: (r) => r["namespace"] == "{namespace}")
            |> filter(fn: (r) => r["pod_name"] =~ { "/%s-%s/" % (namespace, container_type) })
            |> group(columns: ["container_name"])
            |> aggregateWindow(every: {every}, fn: max, createEmpty: false)
            |> yield(name: "max")
            |> aggregateWindow(every: {every}, fn: mean, createEmpty: false)
            |> yield(name: "mean")
    """
    yield from _query_stream(flux_script)


def query_memory_usage(
        namespace, container_type, start, stop, every) -> Iterator[FluxRecord]:
    flux_script = f"""
        from(bucket: "kubernetes")
            |> range(start: {start}, stop: {stop})
            |> filter(fn: (r) => r["_measurement"] == "kubernetes_pod_container")
            |> filter(fn: (r) => r["_field"] == "memory_usage_bytes")
            |> filter(fn: (r) => r["namespace"] == "{namespace}")
            |> filter(fn: (r) => r["pod_name"] =~ { "/%s-%s/" % (namespace, container_type) })
            |> group(columns: ["container_name"])
            |> aggregateWindow(every: {every}, fn: max, createEmpty: false)
            |> yield(name: "max")
            |> aggregateWindow(every: {every}, fn: mean, createEmpty: false)
            |> yield(name: "mean")
    """
    yield from _query_stream(flux_script)


def query_network_usage(
        namespace, container_type, start, stop, every) -> Iterator[FluxRecord]:
    flux_script = f"""
        from(bucket: "kubernetes")
            |> range(start: {start}, stop: {stop})
            |> filter(fn: (r) => r["_measurement"] == "kubernetes_pod_network")
            |> filter(fn: (r) => r["_field"] == "rx_bytes" or r["_field"] == "tx_bytes")
            |> filter(fn: (r) => r["namespace"] == "{namespace}")
            |> filter(fn: (r) => r["pod_name"] =~ { "/%s-%s/" % (namespace, container_type) })
            |> group(columns: ["container_name", "_field"])
            |> aggregateWindow(every: {every}, fn: max, createEmpty: false)
            |> difference(nonNegative: true)
            |> pivot(
                rowKey:["_time"],
                columnKey: ["_field"],
                valueColumn: "_value"
            )
            |> limit(n:3000)
    """
    yield from _query_stream(flux_script)
