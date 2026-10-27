"""The Sentinel client: a small, dependency-light daemon that registers with a CVEngine instance and runs nmap, naabu
and nuclei work it is leased, reporting typed results back. It has no Django dependency and ships as a standalone
Docker image (see ../Dockerfile, ../docker-compose.yml); its only coupling to the web app is the REST contract
documented in docs/AGENT-API.md.
"""
