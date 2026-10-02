# Static marketing site deployment

This image serves only the static files in this directory. It has no Beacon
application, database, credentials, or host port requirement. NGINX runs as
the upstream unprivileged UID 101 and listens on container port 8080. Its
base image is digest-pinned; update the digest only after reviewing the
upstream release and rebuilding/testing the image.

## Build and smoke-test locally

From the public Beacon repository root:

```sh
docker build --pull -f site/Dockerfile -t beacon-marketing:local .
docker run --detach --rm --name beacon-marketing-smoke \
  --publish 127.0.0.1:8088:8080 \
  --read-only --tmpfs /tmp:size=16m,noexec,nosuid \
  beacon-marketing:local
curl --fail --silent --show-error http://127.0.0.1:8088/
curl --fail --silent --show-error http://127.0.0.1:8088/robots.txt
docker stop beacon-marketing-smoke
```

The local port is only for this disposable smoke test. Production should use
the existing homeserver `public` Docker network and Cloudflare Tunnel, with
no published host port. Keep the Beacon application and database on their
existing private network; only a separate static-site container should be
reachable by Cloudflared. Keep hostname routing, Compose and systemd wiring in
the operator's `personal-os` configuration repository, not this product repo.

For production, build the image from a reviewed immutable Beacon commit, tag
it with that commit ID, and run it under the managed Compose/systemd service.
Route `beacon.grislabs.com` only to the static service alias. Preserve the
catch-all 404 rule. To roll back, restore the previous tunnel config and
restart Cloudflared, then stop the new static service; never change the
Beacon app's network membership as a rollback/deployment shortcut.

After deployment, check from outside the tailnet: homepage, all guide URLs,
downloads, assets, canonical URLs, sitemap, robots, security headers, and
that the app/report route is not exposed. Do not treat a simulated crawler
user-agent as proof that Google, Bing, or OAI-SearchBot has crawled or indexed
the site.
