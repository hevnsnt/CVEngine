# The AI reviewer (docs/AI-REVIEWER.md): a small image with the reviewer package and its pinned dependencies, nothing else. No cvENGINE
# source, no scanners, no shell tools beyond the base image's. It runs as an unprivileged user on a read-only filesystem (docker-compose.yml).
FROM python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt /opt/reviewer/requirements.txt
RUN pip install --no-cache-dir -r /opt/reviewer/requirements.txt \
    && groupadd --system --gid 10002 reviewer \
    && useradd --system --uid 10002 --gid 10002 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin reviewer

# Into site-packages, owned by root and read-only to the reviewer: `python3 -I` (isolated mode) never puts the working directory on the path.
COPY cvengine_reviewer /usr/local/lib/python3.13/site-packages/cvengine_reviewer
# Readable by the reviewer user whatever the umask of the checkout was: on a host that clones with umask 027 or 077 the files arrive mode 640 or 600,
# and the unprivileged user then cannot import its own package (the container crash-loops with PermissionError).
RUN chmod -R a+rX /usr/local/lib/python3.13/site-packages/cvengine_reviewer
WORKDIR /tmp
USER 10002:10002
ENTRYPOINT ["python3", "-I", "-m", "cvengine_reviewer"]
