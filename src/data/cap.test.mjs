import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCap } from './cap.js';
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
  assert.equal(CAP_SOURCES.nws.format, 'atom');
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
  assert.equal(CAP_SOURCES.eccc.enabled, false);
  const old = process.env.CAP_OPT_IN_SOURCES;
  process.env.CAP_OPT_IN_SOURCES = 'eccc';
  assert.ok(
    capProxy({
      sources: { eccc: CAP_SOURCES.eccc },
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

test('NWS Atom links use the registered CAP document path', () => {
  const source = CAP_SOURCES.nws;
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
