from datetime import datetime

from api.utils import get_influxdb_client


class InfluxProxy(object):
    def __init__(self):
        self.c = get_influxdb_client()

    def query(self, q):
        rs = self.c.query(q)
        return rs

    def write_points(self, body):
        self.c.write_points(body)

    @staticmethod
    def drycc_volume_manifest(namespace, volume_name, **kwargs):
        data = [{
            "measurement": "drycc_volume",
            "tags": {
                "volume_name": volume_name,
                "namespace": namespace
            },
            "time": datetime.now(),
            "fields": {
                "size": kwargs.get('size')
            }
        }]
        return data

    @staticmethod
    def drycc_limit_manifest(namespace, type, **kwargs):
        data = [{
            "measurement": "drycc_limit",
            "tags": {
                "type": type,
                "namespace": namespace
            },
            "time": datetime.now(),
            "fields": {
                "cpu": kwargs.get('cpu'),
                "memory": kwargs.get('memory')
            }
        }]
        return data

    @staticmethod
    def drycc_resource_manifest(namespace, name, **kwargs):
        data = [{
            "measurement": "drycc_resource",
            "tags": {
                "name": name,  # resource name
                "namespace": namespace
            },
            "time": datetime.now(),
            "fields": {
                "plan": kwargs.get('plan')
            }
        }]
        return data


influx_client = InfluxProxy()

if __name__ == '__main__':
    q = '''SELECT last("rx_bytes") FROM "kubernetes_pod_network"
       WHERE ("namespace" = 'py3django3') AND time >= now() - 5m
       GROUP BY time(5m), "pod_name" fill(null)'''
    influx_client.query(q)
