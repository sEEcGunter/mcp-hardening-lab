.PHONY: test demo

ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

test:
	cd $(ROOT) && python3 -m pytest

demo:
	cd $(ROOT) && python3 labs/01-git-config-exec/make_fixture.py --demo
	cd $(ROOT) && python3 labs/02-policy-normalization/fixed.py --demo
