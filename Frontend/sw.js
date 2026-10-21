// Trident Fitness service worker — push notifications only.
// It never caches or intercepts page loads, so app updates still arrive as soon as they are published.

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

self.addEventListener('push', event => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) { data = { body: event.data ? event.data.text() : '' }; }
  const options = {
    body: data.body || '',
    icon: 'Icons/icon-192.png',
    badge: 'Icons/icon-192.png',
    data: { open: data.open || '' }
  };
  if (data.tag) { options.tag = data.tag; options.renotify = true; }
  event.waitUntil(self.registration.showNotification(data.title || 'Trident Fitness', options));
});

// Tapping a notification opens the app (or brings it forward) on the message, profile or post it is about.
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const open = (event.notification.data && event.notification.data.open) || '';
  const url = new URL('app.html' + (open ? '?open=' + encodeURIComponent(open) : ''), self.registration.scope).href;
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of windows) {
      if (client.url.indexOf('app.html') >= 0) {
        await client.focus();
        if (open) client.postMessage({ type: 'trident-open', open });
        return;
      }
    }
    await self.clients.openWindow(url);
  })());
});
