#!/usr/bin/env bash

set -euo pipefail
set -x

for file in 3.111.0; do
    c-at-e-file-server local --toml fastly.toml --name "polyfill-library-$file" -- "./polyfill-libraries/polyfill-library-$file/polyfills/__dist/"
done

# c-at-e-file-server local --toml fastly.toml --name "site" -- "./dist/"