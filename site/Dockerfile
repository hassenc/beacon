FROM nginxinc/nginx-unprivileged:stable-alpine3.24@sha256:4714e0b1b2577eaa1a6131d07c958b67f0eb68e6d0521e90c6e5287db8cf0bc5

COPY --chown=101:101 site/nginx.conf /etc/nginx/conf.d/default.conf
COPY --chown=101:101 site/index.html site/robots.txt site/sitemap.xml site/config.js site/site.js /usr/share/nginx/html/
COPY --chown=101:101 site/assets/ /usr/share/nginx/html/assets/
COPY --chown=101:101 site/guides/ /usr/share/nginx/html/guides/
COPY --chown=101:101 site/downloads/ /usr/share/nginx/html/downloads/
