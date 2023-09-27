# Drycc Controller

[![Build Status](https://woodpecker.drycc.cc/api/badges/drycc/controller/status.svg)](https://woodpecker.drycc.cc/drycc/controller)
[![codecov.io](https://codecov.io/github/drycc/controller/coverage.svg?branch=main)](https://codecov.io/github/drycc/controller?branch=main)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fdrycc%2Fcontroller.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fdrycc%2Fcontroller?ref=badge_shield)

Drycc (pronounced DAY-iss) Workflow is an open source Platform as a Service (PaaS) that adds a developer-friendly layer to any [Kubernetes](http://kubernetes.io) cluster, making it easy to deploy and manage applications on your own servers.

For more information about the Drycc Workflow, please visit the main project page at https://github.com/drycc/workflow.

We welcome your input! If you have feedback, please [submit an issue][issues]. If you'd like to participate in development, please read the "Development" section below and [submit a pull request][prs].

# About

The Controller is the central API server for [Drycc Workflow][workflow]. It is installed on a [Kubernetes](http://kubernetes.io) cluster, making it easy to deploy and manage applications on your own cluster. Below is a non-exhaustive list of things it can do:

* Create a new application
* Delete an application
* Scale an application
* Configure an application
* Create a new user

# Development

The Drycc project welcomes contributions from all developers. The high-level process for development matches many other open source projects. See below for an outline.

* Fork this repository
* Make your changes
* [Submit a pull request][prs] (PR) to this repository with your changes, and unit tests whenever possible.
  * If your PR fixes any [issues][issues], make sure you write Fixes #1234 in your PR description (where #1234 is the number of the issue you're closing)
* Drycc project maintainers will review your code.
* After two maintainers approve it, they will merge your PR.

## Prerequisites

### Podman

Unit tests and code linters for controller run in a container with your local code directory
mounted in. You need [Podman][] to run `make test`.

### Kubernetes

You'll want to test your code changes interactively in a working Kubernetes cluster. Follow the
[installation instructions][install-k8s] if you need Kubernetes.

### Workflow Installation

After you have a working Kubernetes cluster, you're ready to [install Workflow](https://drycc.com/docs/workflow/installing-workflow/).

## Testing Your Code

When you've built your new feature or fixed a bug, make sure you've added appropriate unit tests and run `make test` to ensure your code works properly.

Also, since this component is central to the platform, it's recommended that you manually test and verify that your feature or fix works as expected. To do so, ensure the following environment variables are set:

* `DRYCC_REGISTRY` - A Container registry that you have push access to and your Kubernetes cluster can pull from
  * If this is [Drycc Registry](https://registry.drycc.cc/), leave this variable empty
* `IMAGE_PREFIX` - The organization in the Container repository. This defaults to `drycc`, but if you don't have access to that organization, set this to one you have push access to.
* `SHORT_NAME` (optional) - The name of the image. This defaults to `controller`
* `VERSION` (optional) - The tag of the Container image. This defaults to the current Git SHA (the output of `git rev-parse --short HEAD`)

Then, run `make deploy` to build and push a new Container image with your changes and replace the existing one with your new one in the Kubernetes cluster. See below for an example with appropriate environment variables.

```console
export IMAGE_PREFIX=arschles
make deploy
```

After the `make deploy` finishes, a new pod will be launched but may not be running. You'll need to wait until the pod is listed as `Running` and the value in its `Ready` column is `1/1`. Use the following command watch the pod's status:

```console
kubectl get pod --namespace=drycc -w | grep drycc-controller
```

[install-k8s]: https://kubernetes.io/docs/setup/pick-right-solution
[issues]: https://github.com/drycc/controller/issues
[prs]: https://github.com/drycc/controller/pulls
[workflow]: https://github.com/drycc/workflow
[Podman]: https://podman.io/


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fdrycc%2Fcontroller.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fdrycc%2Fcontroller?ref=badge_large)
