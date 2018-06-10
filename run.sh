#!/bin/bash

PYTHONPATH=. pspdr measure -i enp0s3 evilbit < targets.ndjson | tee results.ndjson
