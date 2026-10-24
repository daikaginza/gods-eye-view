import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseCap, parseEcccAlerts, parseNwsAlerts } from './cap.js';
import { createCapState } from './capState.js';
import {
  allowedCapUrl,
  CAP_SOURCES,
  capProxy,
  extractCapLinks,
} from '../../server/providers/cap.js';

test('catalogue keeps supplied endpoints and formats', () => {
  assert.equal(
    CAP_SOURCES.inmet.url,
    'https://apiprevmet3.inmet.gov.br/avisos/rss',
  );
  assert.equal(CAP_SOURCES.nws.format, 'nws-geojson');
  assert.equal(CAP_SOURCES.eccc.format, 'eccc-geojson');
  assert.equal(CAP_SOURCES.eccc.enabled, true);
  assert.equal(CAP_SOURCES['met-norway'].format, 'cap');
});
test('pure RSS/Atom link whitelist accepts same path only', () => {
  const s = CAP_SOURCES.inmet;
  assert.deepEqual(
    extractCapLinks(
      '<item><link>https://apiprevmet3.inmet.gov.br/avisos/rss/a.xml</link></item><link href="https://evil.example/x"/>',
      s,
    ),
    ['https://apiprevmet3.inmet.gov.br/avisos/rss/a.xml'],
  );
});
test('uncertain catalogues stay disabled and opt-in is recognized', () => {
  assert.equal(CAP_SOURCES.meteoalarm.enabled, false);
  const old = process.env.CAP_OPT_IN_SOURCES;
  process.env.CAP_OPT_IN_SOURCES = 'meteoalarm';
  assert.ok(
    capProxy({
      sources: { meteoalarm: CAP_SOURCES.meteoalarm },
      fetchImpl: async () => {
        throw Error('offline');
      },
    }),
  );
  if (old === undefined) delete process.env.CAP_OPT_IN_SOURCES;
  else process.env.CAP_OPT_IN_SOURCES = old;
});

const cap = (body) =>
  `<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2"><identifier>a</identifier><sender>x</sender><sent>2026-01-01T00:00:00Z</sent>${body}</alert>`;
test('default namespace', () =>
  assert.equal(parseCap(cap('<msgType>Alert</msgType>'))[0].msgType, 'Alert'));
test('prefixed namespace', () =>
  assert.equal(
    parseCap(
      cap('<cap:info xmlns:cap="urn:x"><cap:event>Fire</cap:event></cap:info>'),
    )[0].info[0].event,
    'Fire',
  ));
test('CDATA and entities', () =>
  assert.equal(
    parseCap(
      cap('<info><description><![CDATA[A &amp; B]]></description></info>'),
    )[0].info[0].description,
    'A & B',
  ));
test('info fields and areas', () => {
  const a = parseCap(
    cap(
      '<info><urgency>Immediate</urgency><area><areaDesc>Zone</areaDesc><geocode><value>1</value></geocode></area></info>',
    ),
  )[0];
  assert.equal(a.info[0].urgency, 'Immediate');
  assert.equal(a.info[0].areas[0].description, 'Zone');
});
test('polygon lat lon', () =>
  assert.deepEqual(
    parseCap(cap('<info><area><polygon>1,2 3,4 5,6</polygon></area></info>'))[0]
      .info[0].areas[0].geometry.coordinates[0],
    [1, 2],
  ));
test('circle', () =>
  assert.equal(
    parseCap(cap('<info><area><circle>1,2 5</circle></area></info>'))[0].info[0]
      .areas[0].geometry.radiusKm,
    5,
  ));
test('truncated and malicious XML rejected', () => {
  assert.throws(() => parseCap(cap('<info>')));
  assert.throws(() => parseCap('<!DOCTYPE alert [<!ENTITY x "y">]><alert/>'));
});
test('byte and item limits', () => {
  assert.throws(() =>
    parseCap(cap('<description>x</description>'), { maxBytes: 5 }),
  );
  assert.throws(() =>
    parseCap(
      '<alert><identifier>x</identifier></alert><alert><identifier>y</identifier></alert>',
      { maxItems: 1 },
    ),
  );
});
test('alert then update preserves target identity', () => {
  const s = createCapState();
  s.ingest([
    { identifier: 'a', sent: '2026-01-01T00:00:00Z', msgType: 'Alert' },
  ]);
  assert.equal(
    s.ingest([
      {
        identifier: 'u',
        references: 'sender,a,2026-01-01T00:00:00Z',
        sent: '2026-01-02T00:00:00Z',
        msgType: 'Update',
      },
    ])[0].identifier,
    'a',
  );
});
test('update whose original was never seen is served', () => {
  // A feed of active alerts lists the current Update, not the Alert it
  // replaced; a cold start must still show it.
  const s = createCapState();
  const out = s.ingest([
    {
      identifier: 'u',
      references: 'sender,a,2026-01-01T00:00:00Z',
      sent: '2026-01-02T00:00:00Z',
      msgType: 'Update',
    },
  ]);
  assert.equal(out.length, 1);
  assert.equal(out[0].identifier, 'a');
  s.ingest([{ identifier: 'c', references: 'sender,a,t', msgType: 'Cancel' }]);
  assert.equal(
    s.ingest([
      {
        identifier: 'u2',
        references: 'sender,a,2026-01-01T00:00:00Z',
        sent: '2026-01-03T00:00:00Z',
        msgType: 'Update',
      },
    ]).length,
    0,
    'a cancelled chain stays cancelled',
  );
});
test('cancel prevents resurrection and old versions', () => {
  const s = createCapState();
  s.ingest([
    { identifier: 'a', sent: '2026-01-02T00:00:00Z', msgType: 'Alert' },
  ]);
  s.ingest([{ identifier: 'c', references: 'sender,a,t', msgType: 'Cancel' }]);
  assert.equal(
    s.ingest([
      { identifier: 'a', sent: '2026-01-03T00:00:00Z', msgType: 'Alert' },
    ]).length,
    0,
  );
});
test('expiration uses injected now', () => {
  let t = 0;
  const s = createCapState({ now: () => t });
  s.ingest([
    {
      identifier: 'a',
      sent: '2026-01-01T00:00:00Z',
      msgType: 'Alert',
      info: [{ expires: '1970-01-01T00:00:10Z' }],
    },
  ]);
  t = 11000;
  assert.equal(s.snapshot().length, 0);
});
test('provider uses catalog and tolerates partial failure', async () => {
  const xml = cap('');
  const fetchImpl = async (url) => {
    if (url === CAP_SOURCES['met-norway'].url)
      return { ok: true, headers: new Headers(), text: async () => xml };
    throw Error('offline');
  };
  const p = capProxy({
    fetchImpl,
    sources: {
      good: CAP_SOURCES['met-norway'],
      bad: { url: 'https://catalog.invalid', region: 'x' },
    },
  });
  const res = {
    body: '',
    setHeader() {},
    end(x) {
      this.body = x;
    },
  };
  await p.handle({ url: '/api/cap' }, res, () => {});
  assert.equal(JSON.parse(res.body).alerts.length, 1);
});

const capAlert = ({
  identifier,
  sent,
  msgType = 'Alert',
  references = '',
  event = '',
}) =>
  `<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2"><identifier>${identifier}</identifier><sender>x</sender><sent>${sent}</sent><msgType>${msgType}</msgType>${references ? `<references>${references}</references>` : ''}${event ? `<info><event>${event}</event></info>` : ''}</alert>`;
const okResponse = (body) => ({
  ok: true,
  headers: new Headers(),
  text: async () => body,
});
const runProxy = async (proxy) => {
  const res = {
    body: '',
    setHeader() {},
    end(x) {
      this.body = x;
    },
  };
  await proxy.handle({ url: '/api/cap' }, res, () => {});
  return JSON.parse(res.body);
};

test('Atom links use the registered CAP document path', () => {
  const source = {
    url: 'https://api.weather.gov/alerts/active.atom',
    documentPathPrefix: '/alerts',
  };
  assert.deepEqual(
    extractCapLinks(
      '<link href="https://api.weather.gov/alerts/urn:oid:test.cap"/><link href="https://api.weather.gov/alerts-evil/test.cap"/><link href="https://user@api.weather.gov/alerts/test.cap"/>',
      source,
    ),
    ['https://api.weather.gov/alerts/urn:oid:test.cap'],
  );
  assert.equal(
    allowedCapUrl(source, 'https://api.weather.gov/alerts-evil/test.cap'),
    false,
  );
});

test('provider applies CAP lifecycle before serving alerts', async () => {
  const xml =
    capAlert({
      identifier: 'a',
      sent: '2026-01-01T00:00:00Z',
      event: 'Original',
    }) +
    capAlert({
      identifier: 'u',
      sent: '2026-01-02T00:00:00Z',
      msgType: 'Update',
      references: 'x,a,2026-01-01T00:00:00Z',
      event: 'Updated',
    });
  const proxy = capProxy({
    fetchImpl: async () => okResponse(xml),
    sources: {
      one: {
        url: 'https://cap.example/alerts.xml',
        region: 'x',
        format: 'cap',
        enabled: true,
      },
    },
  });
  const body = await runProxy(proxy);
  assert.equal(body.alerts.length, 1);
  assert.equal(body.alerts[0].identifier, 'a');
  assert.equal(body.alerts[0].info[0].event, 'Updated');
});

test('cold clients share one publisher refresh and reuse the cache', async () => {
  let calls = 0;
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const proxy = capProxy({
    fetchImpl: async () => {
      calls += 1;
      await gate;
      return okResponse(cap('<msgType>Alert</msgType>'));
    },
    sources: {
      one: {
        url: 'https://cap.example/alerts.xml',
        region: 'x',
        format: 'cap',
        enabled: true,
      },
    },
    cacheTtlMs: 60000,
  });
  const first = runProxy(proxy);
  const second = runProxy(proxy);
  await Promise.resolve();
  assert.equal(calls, 1);
  release();
  await Promise.all([first, second]);
  await runProxy(proxy);
  assert.equal(calls, 1);
});

test('cold total outage is not cached as an empty success', async () => {
  let calls = 0;
  const proxy = capProxy({
    fetchImpl: async () => {
      calls += 1;
      if (calls === 1) throw Error('offline');
      return okResponse(
        capAlert({
          identifier: 'recovered',
          sent: '2026-01-01T00:00:00Z',
        }),
      );
    },
    sources: {
      one: {
        url: 'https://cap.example/alerts.xml',
        region: 'x',
        format: 'cap',
        enabled: true,
      },
    },
    cacheTtlMs: 60000,
  });
  const first = await runProxy(proxy);
  assert.equal(first.alerts.length, 0);
  assert.equal(first.generatedAt, null);
  const second = await runProxy(proxy);
  assert.equal(calls, 2, 'a cold outage gets another acquisition attempt');
  assert.equal(second.alerts.length, 1);
  assert.equal(second.alerts[0].identifier, 'recovered');
  assert.ok(second.generatedAt);
});

test('document limit is global across RSS sources', async () => {
  let documentFetches = 0;
  const sources = {
    one: {
      url: 'https://one.example/feed',
      region: 'one',
      format: 'rss',
      enabled: true,
    },
    two: {
      url: 'https://two.example/feed',
      region: 'two',
      format: 'rss',
      enabled: true,
    },
  };
  const fetchImpl = async (url) => {
    if (url.endsWith('/feed')) {
      return okResponse(
        `<link href="${url}/a.xml"/><link href="${url}/b.xml"/>`,
      );
    }
    documentFetches += 1;
    return okResponse(
      capAlert({
        identifier: String(documentFetches),
        sent: '2026-01-01T00:00:00Z',
      }),
    );
  };
  const proxy = capProxy({
    fetchImpl,
    sources,
    maxDocuments: 2,
    concurrency: 2,
  });
  await runProxy(proxy);
  assert.equal(documentFetches, 2);
});

const nwsFeature = (properties, geometry = null) => ({
  type: 'Feature',
  geometry,
  properties: {
    id: 'urn:oid:1',
    sender: 'w-nws.webmaster@noaa.gov',
    sent: '2026-01-02T00:00:00-05:00',
    messageType: 'Alert',
    status: 'Actual',
    scope: 'Public',
    references: [],
    language: 'en-US',
    category: 'Met',
    event: 'Flood Warning',
    urgency: 'Immediate',
    severity: 'Severe',
    certainty: 'Observed',
    headline: 'Flood Warning issued',
    description: 'River above flood stage.',
    instruction: 'Turn around, do not drown.',
    onset: '2026-01-02T00:00:00-05:00',
    expires: '2026-01-03T00:00:00-05:00',
    areaDesc: 'Polk, IA',
    geocode: { UGC: ['IAC153'], SAME: ['019153'] },
    ...properties,
  },
});

test('NWS GeoJSON maps to the CAP alert shape', () => {
  const [alert] = parseNwsAlerts(
    JSON.stringify({
      features: [
        nwsFeature(
          {
            messageType: 'Update',
            references: [
              {
                identifier: 'urn:oid:0',
                sender: 'w-nws.webmaster@noaa.gov',
                sent: '2026-01-01T00:00:00-05:00',
              },
            ],
          },
          {
            type: 'Polygon',
            coordinates: [
              [
                [-93.6, 41.5],
                [-93.5, 41.5],
                [-93.5, 41.6],
                [-93.6, 41.5],
              ],
            ],
          },
        ),
      ],
    }),
  );
  assert.equal(alert.identifier, 'urn:oid:1');
  assert.equal(alert.msgType, 'Update');
  assert.equal(
    alert.references,
    'w-nws.webmaster@noaa.gov,urn:oid:0,2026-01-01T00:00:00-05:00',
  );
  assert.equal(alert.info[0].event, 'Flood Warning');
  assert.equal(alert.info[0].severity, 'Severe');
  assert.equal(alert.info[0].areas[0].description, 'Polk, IA');
  assert.equal(alert.info[0].areas[0].geocode, 'IAC153');
  assert.deepEqual(alert.info[0].areas[0].geometry, {
    type: 'polygon',
    coordinates: [
      [41.5, -93.6],
      [41.5, -93.5],
      [41.6, -93.5],
      [41.5, -93.6],
    ],
  });
});

test('NWS GeoJSON rejects bad documents and bad geometry', () => {
  assert.throws(() => parseNwsAlerts('<html>'));
  assert.throws(() => parseNwsAlerts('{}'));
  assert.throws(() =>
    parseNwsAlerts(JSON.stringify({ features: [{}, {}] }), { maxItems: 1 }),
  );
  const [alert] = parseNwsAlerts(
    JSON.stringify({
      features: [
        nwsFeature(
          {},
          {
            type: 'Polygon',
            coordinates: [
              [
                [-93.6, 141.5],
                [-93.5, 41.5],
                [-93.5, 41.6],
              ],
            ],
          },
        ),
        { properties: { event: 'no id' } },
      ],
    }),
  );
  assert.equal(alert.info[0].areas[0].geometry, null);
});

test('NWS source is one request with its own byte limit', async () => {
  const urls = [];
  const accepts = [];
  const body = JSON.stringify({
    features: [
      nwsFeature({ id: 'urn:oid:a' }),
      nwsFeature({
        id: 'urn:oid:b',
        messageType: 'Update',
        references: [{ identifier: 'urn:oid:never-seen', sent: 't' }],
      }),
    ],
  });
  const proxy = capProxy({
    fetchImpl: async (url, init) => {
      urls.push(url);
      accepts.push(init.headers.accept);
      return okResponse(body);
    },
    sources: { nws: CAP_SOURCES.nws },
    maxBytes: 16,
    maxDocuments: 1,
    now: () => Date.parse('2026-01-02T12:00:00Z'),
  });
  const result = await runProxy(proxy);
  assert.deepEqual(urls, ['https://api.weather.gov/alerts/active']);
  assert.deepEqual(accepts, ['application/geo+json']);
  assert.deepEqual(result.alerts.map((a) => a.identifier).sort(), [
    'urn:oid:a',
    'urn:oid:never-seen',
  ]);
  assert.equal(result.alerts[0].region, 'US');
});

// Trimmed from the live MSC GeoMet weather-alerts collection (2026-10-24,
// see fixtures/README.md): a Newfoundland wind warning with four ended areas
// and one continued, a winter storm warning that replaced a wind warning on
// two areas (changed_from), the ended areas of a Saskatchewan statement, and
// one area of an Ontario statement.
const ecccFixture = readFileSync(
  new URL('./fixtures/eccc-geomet-alerts.json', import.meta.url),
  'utf8',
);
const ecccById = (text = ecccFixture) =>
  Object.fromEntries(parseEcccAlerts(text).map((a) => [a.identifier, a]));

test('ECCC GeoMet areas are grouped into one alert per ECCC alert id', () => {
  const alerts = ecccById();
  assert.deepEqual(Object.keys(alerts).sort(), [
    '13704565643585161202610240501',
    '202949082276051729202610230503',
    '33513774847910979202610220507',
    '453197841867508436202610220501',
  ]);
  const storm = alerts['13704565643585161202610240501'];
  assert.equal(storm.msgType, 'Alert');
  assert.equal(storm.sent, '2026-10-24T01:37:04.565Z');
  assert.deepEqual(
    storm.info.map((i) => i.language),
    ['en-CA', 'fr-CA'],
  );
  const [en, fr] = storm.info;
  assert.equal(en.event, 'winter storm warning');
  assert.equal(en.headline, 'winter storm warning (yellow)');
  assert.equal(fr.headline, 'avertissement de tempête hivernale (jaune)');
  assert.equal(en.onset, '2026-10-24T12:00:00.000Z');
  assert.equal(en.expires, '2026-10-24T17:37:04.565Z');
  assert.match(en.description, /^A significant fall storm/);
  assert.deepEqual(
    en.areas.map((a) => [a.description, a.geocode]),
    [
      ['Arviat', 'fea1-2502'],
      ['Churchill', 'fea1-1510'],
    ],
  );
  assert.ok(en.areas.every((a) => a.geometry?.type === 'polygon'));
  assert.ok(fr.areas.every((a) => a.geometry === null));
});

test('ECCC ended areas are dropped and an all-ended alert is a Cancel', () => {
  const alerts = ecccById();
  const wind = alerts['33513774847910979202610220507'];
  assert.deepEqual(
    wind.info[0].areas.map((a) => a.description),
    ['Avalon Peninsula Southeast'],
  );
  assert.equal(wind.info[0].expires, '2026-10-24T07:00:40.350Z');
  const ended = alerts['453197841867508436202610220501'];
  assert.equal(ended.msgType, 'Cancel');
  assert.deepEqual(ended.info, []);
  // Served through the lifecycle state: the cancelled statement disappears
  // even though its last version has not expired yet.
  const state = createCapState({
    now: () => Date.parse('2026-10-23T12:00:00Z'),
  });
  state.ingest([
    {
      ...ended,
      msgType: 'Alert',
      info: [{ expires: '2026-10-24T03:14:16.916Z' }],
    },
  ]);
  assert.equal(state.snapshot().length, 1);
  state.ingest([ended]);
  assert.equal(state.snapshot().length, 0);
});

test('ECCC sent follows the newest area change, ended areas included', () => {
  const doc = JSON.parse(ecccFixture);
  const area = doc.features.find(
    (f) => f.id === '33513774847910979202610220507_fea1-861',
  );
  area.properties.publication_datetime = '2026-10-24T03:03:34.000Z';
  const shrunk = ecccById(JSON.stringify(doc))['33513774847910979202610220507'];
  assert.equal(shrunk.sent, '2026-10-24T03:03:34.000Z');
  const state = createCapState({
    now: () => Date.parse('2026-10-24T03:30:00Z'),
  });
  const wider = {
    ...shrunk,
    sent: '2026-10-24T02:21:40.350Z',
    info: [{ ...shrunk.info[0], areas: [{}, {}] }],
  };
  state.ingest([wider]);
  const [served] = state.ingest([shrunk]);
  assert.equal(served.info[0].areas.length, 1);
});

test('ECCC polygons are [lat, lon] and severity follows the alert colour', () => {
  const alerts = ecccById();
  const [first] =
    alerts['33513774847910979202610220507'].info[0].areas[0].geometry
      .coordinates;
  // GeoJSON [lon, lat] on the Avalon Peninsula becomes CAP's lat,lon order.
  assert.deepEqual(first, [46.79933249, -52.9110835]);
  assert.equal(
    alerts['33513774847910979202610220507'].info[0].severity,
    'Moderate',
  );
  assert.equal(
    alerts['202949082276051729202610230503'].info[0].severity,
    'Minor',
  );
  const doc = JSON.parse(ecccFixture);
  const recolour = (colour, type = 'warning') => {
    for (const f of doc.features) {
      f.properties.risk_colour_en = colour;
      f.properties.alert_type = type;
    }
    return ecccById(JSON.stringify(doc))['13704565643585161202610240501']
      .info[0].severity;
  };
  assert.equal(recolour('orange'), 'Severe');
  assert.equal(recolour('red'), 'Extreme');
  assert.equal(recolour(null), 'Unknown');
  assert.equal(recolour(null, 'statement'), 'Minor');
});

test('ECCC GeoMet rejects bad documents and skips unkeyed features', () => {
  assert.throws(() => parseEcccAlerts('<html>'));
  assert.throws(() => parseEcccAlerts('{"type":"FeatureCollection"}'));
  assert.throws(() =>
    parseEcccAlerts(JSON.stringify({ features: [{}, {}] }), { maxItems: 1 }),
  );
  const doc = JSON.parse(ecccFixture);
  const [good] = doc.features.filter(
    (f) => f.id === '202949082276051729202610230503_fea1-1170',
  );
  const badRing = structuredClone(good);
  badRing.id = 'x_fea1-1';
  badRing.properties.feature_id = 'fea1-1';
  badRing.geometry.coordinates[0][1] = [-83, 141];
  const parsed = parseEcccAlerts(
    JSON.stringify({
      features: [
        good,
        badRing,
        { ...good, id: 'fea1-1170' },
        { ...good, id: 42 },
        { id: 'y_fea1-2', properties: null },
      ],
    }),
  );
  assert.deepEqual(
    parsed.map((a) => a.identifier),
    ['202949082276051729202610230503', 'x'],
  );
  assert.equal(parsed[1].info[0].areas[0].geometry, null);
});

test('ECCC source is one request with its own byte and time limits', async () => {
  const urls = [];
  const accepts = [];
  const proxy = capProxy({
    fetchImpl: async (url, init) => {
      urls.push(url);
      accepts.push(init.headers.accept);
      // GeoMet takes seconds to answer; the global CAP timeout does not apply.
      await new Promise((resolve) => setTimeout(resolve, 30));
      if (init.signal.aborted) throw Error('aborted');
      return okResponse(ecccFixture);
    },
    sources: { eccc: CAP_SOURCES.eccc },
    maxBytes: 16,
    maxDocuments: 1,
    timeoutMs: 5,
    now: () => Date.parse('2026-10-24T03:00:00Z'),
  });
  const result = await runProxy(proxy);
  assert.deepEqual(urls, [
    'https://api.weather.gc.ca/collections/weather-alerts/items?f=json&limit=10000',
  ]);
  assert.deepEqual(accepts, ['application/geo+json']);
  assert.deepEqual(result.alerts.map((a) => a.identifier).sort(), [
    '13704565643585161202610240501',
    '202949082276051729202610230503',
    '33513774847910979202610220507',
  ]);
  assert.ok(result.alerts.every((a) => a.region === 'Canada'));
  // Past the wind warning's expires the lifecycle state drops it as usual.
  const later = capProxy({
    fetchImpl: async () => okResponse(ecccFixture),
    sources: { eccc: CAP_SOURCES.eccc },
    now: () => Date.parse('2026-10-24T08:00:00Z'),
  });
  assert.deepEqual(
    (await runProxy(later)).alerts.map((a) => a.identifier).sort(),
    ['13704565643585161202610240501', '202949082276051729202610230503'],
  );
});
