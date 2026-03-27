# Copilot UI — Malcolm service Dockerfile
# Follows Malcolm's Dockerfiles/{service}.Dockerfile convention
# Multi-stage build: Node.js build → Nginx serve
#
# Build context: the Malcolm repository root
# Usage: docker build -f Dockerfiles/copilot-ui.Dockerfile -t ghcr.io/idaholab/malcolm/copilot-ui:latest .

FROM node:18-alpine AS build

LABEL maintainer="malcolm@inl.gov"

WORKDIR /app
COPY copilot-ui/package*.json ./
RUN npm ci --no-audit --no-fund
COPY copilot-ui/ .
RUN npm run build

FROM nginx:1.27-alpine

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/cisagov/Malcolm/blob/main/copilot-ui/README.md'
LABEL org.opencontainers.image.source='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.vendor='Cybersecurity and Infrastructure Security Agency'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/copilot-ui'
LABEL org.opencontainers.image.description='Malcolm container providing the Copilot LLM interface'

COPY --from=build /app/dist /usr/share/nginx/html
COPY copilot-ui/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -q --spider http://localhost:3000/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
