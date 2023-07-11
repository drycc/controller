from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource


class ReplicaSet(Resource):
    api_prefix = 'apis'
    api_version = 'apps/v1'
    short_name = 'rs'

    def get(self, namespace, name=None, **kwargs):
        """
        Fetch a single ReplicaSet or a list
        """
        url = '/namespaces/{}/replicasets'
        args = [namespace]
        if name is not None:
            args.append(name)
            url += '/{}'
            message = 'get ReplicaSet "{}" in Namespace "{}"'
        else:
            message = 'get ReplicaSets in Namespace "{}"'

        url = self.api(url, *args)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            args.reverse()  # error msg is in reverse order
            raise KubeHTTPException(response, message, *args)

        return response

    def delete(self, namespace, name):
        url = self.api("/namespaces/{}/replicasets/{}", namespace, name)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'delete ReplicationController "{}" in Namespace "{}"', name, namespace
            )

        return response

    def scale(self, namespace, name, desired, timeout):
        rs = self.get(namespace, name).json()

        current = int(rs['spec']['replicas'])
        if desired == current:
            self.log(namespace, "Not scaling RC {} to {} replicas. Already at desired replicas".format(name, desired))  # noqa
            return
        elif desired != rs['spec']['replicas']:  # RC needs new replica count
            self.log(namespace, "scaling RC {} from {} to {} replicas".format(name, current, desired))  # noqa
            self.scales.update(namespace, name, desired, rs)
            self.wait_until_updated(namespace, name)

        # Double check enough pods are in the required state to service the application
        labels = rs['metadata']['labels']
        containers = rs['spec']['template']['spec']['containers']
        self.pods.wait_until_ready(namespace, containers, labels, desired, timeout)

        # if it was a scale down operation, wait until terminating pods are done
        if int(desired) < int(current):
            self.pods.wait_until_terminated(namespace, labels, current, desired)

    def wait_until_updated(self, namespace, name):
        """
        Looks at status/observedGeneration and metadata/generation and
        waits for observedGeneration >= generation to happen, indicates RC is ready

        More information is also available at:
        https://github.com/kubernetes/kubernetes/blob/master/docs/devel/api-conventions.md#metadata
        """
        self.log(namespace, "waiting for ReplicationController {} to get a newer generation (30s timeout)".format(name), 'DEBUG')  # noqa
        for _ in range(30):
            try:
                rs = self.get(namespace, name).json()
                if (
                    "observedGeneration" in rs["status"] and
                    rs["status"]["observedGeneration"] >= rs["metadata"]["generation"]
                ):
                    self.log(namespace, "ReplicationController {} got a newer generation (30s timeout)".format(name), 'DEBUG')  # noqa
                    break

                time.sleep(1)
            except KubeHTTPException as e:
                if e.response.status_code == 404:
                    time.sleep(1)
