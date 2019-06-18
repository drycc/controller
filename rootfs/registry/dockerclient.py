# -*- coding: utf-8 -*-
"""Support the Drycc workflow by manipulating and publishing Docker images."""

import logging
import os

import backoff
from django.conf import settings
from rest_framework.exceptions import PermissionDenied

import docker
import docker.constants
from docker import auth
from docker.errors import APIError
import requests

logger = logging.getLogger(__name__)


class RegistryException(Exception):
    pass


class DockerClient(object):
    """Use the Docker API to pull, tag, build, and push images to drycc-registry."""

    def __init__(self):
        timeout = os.environ.get('DOCKER_CLIENT_TIMEOUT', docker.constants.DEFAULT_TIMEOUT_SECONDS)
        self.client = docker.APIClient(version='auto', timeout=int(timeout))
        self.registry = settings.REGISTRY_HOST + ':' + str(settings.REGISTRY_PORT)

    def login(self, repository, creds=None):
        """Log into a registry if auth is provided"""
        if not creds:
            return

        # parse out the hostname since repo variable is hostname + path
        registry, _ = auth.resolve_repository_name(repository)

        registry_auth = {
            'username': None,
            'password': None,
            'email': None,
            'registry': registry
        }
        registry_auth.update(creds)

        if not registry_auth['username'] or not registry_auth['password']:
            msg = 'Registry auth requires a username and a password'
            logger.error(msg)
            raise PermissionDenied(msg)

        logger.info('Logging into Registry {} with username {}'.format(repository, registry_auth['username']))  # noqa
        response = self.client.login(**registry_auth)
        success = response.get('Status') == 'Login Succeeded' or response.get('username') == registry_auth['username']  # noqa
        if not success:
            raise PermissionDenied('Could not log into {} with username {}'.format(repository, registry_auth['username']))  # noqa

        logger.info('Successfully logged into {} with {}'.format(repository, registry_auth['username']))  # noqa

    def get_port(self, target, drycc_registry=False, creds=None):
        """
        Get a port from a Docker image
        """
        # get the target repository name and tag
        name, _ = docker.utils.parse_repository_tag(target)

        # strip any "http://host.domain:port" prefix from the target repository name,
        # since we always publish to the Drycc registry
        repo, name = auth.split_repo_name(name)

        # log into pull repo
        if not drycc_registry:
            self.login(repo, creds)

        info = self.inspect_image(target)
        if 'ExposedPorts' not in info['Config']:
            return None

        port = int(list(info['Config']['ExposedPorts'].keys())[0].split('/')[0])
        return port

    def publish_release(self, source, target, drycc_registry=False, creds=None):
        """
        Update a source Docker image with environment config and publish
        it to drycc-registry.
        """

        # get the source repository name and tag
        src_name, src_tag = docker.utils.parse_repository_tag(source)
        # get the target repository name and tag
        name, tag = docker.utils.parse_repository_tag(target)
        # strip any "http://host.domain:port" prefix from the target repository name,
        # since we always publish to the Drycc registry
        repo, name = auth.split_repo_name(name)

        # pull the source image from the registry
        # NOTE: this relies on an implementation detail of drycc-builder, that
        # the image has been uploaded already to drycc-registry
        if drycc_registry:
            repo = "{}/{}".format(self.registry, src_name)
        else:
            repo = src_name

        try:
            # log into pull repo
            if creds is not None:
                self.login(repo, creds)

            # pull image from source repository
            self.pull(repo, src_tag)

            # tag the image locally without the repository URL
            image = "{}:{}".format(src_name, src_tag)
            self.tag(image, "{}/{}".format(self.registry, name), tag=tag)

            # push the image to drycc-registry
            self.push("{}/{}".format(self.registry, name), tag)
        except APIError as e:
            raise RegistryException(str(e))

    @backoff.on_exception(backoff.expo, Exception, max_tries=3)
    def pull(self, repo, tag):
        """Pull a Docker image into the local storage graph."""
        check_blacklist(repo)
        logger.info("Pulling Docker image {}:{}".format(repo, tag))
        stream = self.client.pull(repo, tag=tag, stream=True, decode=True)
        log_output(stream, 'pull', repo, tag)

    @backoff.on_exception(backoff.expo, Exception, max_tries=3)
    def push(self, repo, tag):
        """Push a local Docker image to a registry."""
        logger.info("Pushing Docker image {}:{}".format(repo, tag))
        stream = self.client.push(repo, tag=tag, stream=True, decode=True)
        log_output(stream, 'push', repo, tag)

    @backoff.on_exception(backoff.expo, Exception, max_tries=3)
    def tag(self, image, repo, tag):
        """Tag a local Docker image with a new name and tag."""
        check_blacklist(repo)
        logger.info("Tagging Docker image {} as {}:{}".format(image, repo, tag))
        if not self.client.tag(image, repo, tag=tag, force=True):
            raise RegistryException('Tagging {} as {}:{} failed'.format(image, repo, tag))

    @backoff.on_exception(backoff.expo, Exception, max_tries=3)
    def inspect_image(self, target):
        """
        Inspect docker image to gather information from it

        try thrice to find the port before raising exception as docker-py is flaky
        """
        # image already includes the tag, so we split it out here
        repo, tag = docker.utils.parse_repository_tag(target)

        # make sure image is pulled locally already
        self.pull(repo, tag=tag)

        # inspect the image
        return self.client.inspect_image(target)


def check_blacklist(repo):
    """Check a Docker repository name for collision with drycc/* components."""
    blacklisted = [  # NOTE: keep this list up to date!
        'builder', 'controller', 'database', 'dockerbuilder', 'etcd', 'minio', 'registry',
        'router', 'slugbuilder', 'slugrunner', 'workflow', 'workflow-manager',
    ]
    if any("drycc/{}".format(c) in repo for c in blacklisted):
        raise PermissionDenied("Repository name {} is not allowed, as it is reserved by Drycc".format(repo))  # noqa


def log_output(stream, operation, repo, tag):
    """Log a stream at DEBUG level, and raise RegistryException if it contains an error"""
    try:
        for chunk in stream:
            # error handling requires looking at the response body
            if 'error' in chunk:
                stream_error(chunk, operation, repo, tag)
    except requests.packages.urllib3.exceptions.ReadTimeoutError as e:
        message = 'Operation {} timed out for image {}:{}'.format(operation, repo, tag)
        raise RegistryException(message) from e


def stream_error(chunk, operation, repo, tag):
    """Translate docker stream errors into a more digestable format"""
    # grab the generic error and strip the useless Error: portion
    message = chunk['error'].replace('Error: ', '')

    # not all errors provide the code
    if 'code' in chunk['errorDetail']:
        # permission denied on the repo
        if chunk['errorDetail']['code'] == 403:
            message = 'Permission Denied attempting to {} image {}:{}'.format(operation, repo, tag)

    raise RegistryException(message)


def publish_release(source, target, drycc_registry, creds=None):
    return DockerClient().publish_release(source, target, drycc_registry, creds)


def get_port(target, drycc_registry, creds=None):
    return DockerClient().get_port(target, drycc_registry, creds)
