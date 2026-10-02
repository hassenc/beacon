(() => {
  const config = window.BEACON_SITE_CONFIG || {};
  const demoLinks = document.querySelectorAll("[data-demo-request]");
  if (!config.demoRequestUrl) {
    for (const link of demoLinks) link.remove();
    return;
  }
  for (const link of demoLinks) {
    link.href = config.demoRequestUrl;
    link.hidden = false;
  }
})();
