FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends git make \
    && rm -rf /var/lib/apt/lists/* \
    && python -c "import re,subprocess,sys; text=subprocess.check_output(['git','--version'],text=True); major,minor=(int(n) for n in re.search(r'(\\d+)\\.(\\d+)', text).groups()); print(text.strip()); sys.exit(0 if (major, minor) >= (2, 31) else 'git must be >= 2.31 so GIT_CONFIG_COUNT is honored')"

WORKDIR /lab
COPY pyproject.toml README.md LICENSE CHECKLIST.md Makefile ./
COPY labs ./labs
COPY tests ./tests
RUN pip install --no-cache-dir ".[dev]"

CMD ["make", "test", "demo"]
