#!/bin/bash

if [ -n "${CI_COMMIT_TAG}" ]; then
    version=$(curl -Ls https://github.com/drycc/filer/releases|grep /drycc/filer/releases/tag/ | sed -E 's/.*\/drycc\/filer\/releases\/tag\/(v[0-9\.]{1,}(-rc.[0-9]{1,})?)".*/\1/g' | head -1)
    sed -i "s|registry.drycc.cc/drycc/filer:canary|registry.drycc.cc/drycc/filer:${version#v}|g" charts/controller/values.yaml
fi