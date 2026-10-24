const D = { maxBytes: 2097152, maxItems: 512, maxText: 32768 };
const tn = (s) =>
  s
    .slice(1)
    .replace(/^\/?/, '')
    .split(/\s|>/)[0]
    .split(':')
    .pop()
    .toLowerCase();
const dec = (s) =>
  s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(
    /&lt;|&gt;|&quot;|&apos;|&amp;/g,
    (m) =>
      ({
        '&lt;': '<',
        '&gt;': '>',
        '&quot;': '"',
        '&apos;': "'",
        '&amp;': '&',
      })[m],
  );
function tree(x, o) {
  if (/<!DOCTYPE|<!ENTITY|<html[\s>]/i.test(x)) throw Error('invalid_cap');
  const r = { n: 'root', c: [], t: '' },
    s = [r];
  let p = 0,
    k = 0;
  for (const m of x.matchAll(
    /<!--[\s\S]*?-->|<\?[^>]*>|<!\[CDATA\[[\s\S]*?\]\]>|<[^>]+>/g,
  )) {
    if (++k > o.maxItems * 30) throw Error('cap_limit');
    s.at(-1).t += x.slice(p, m.index);
    p = m.index + m[0].length;
    const z = m[0];
    if (z.startsWith('<!--') || z.startsWith('<?')) continue;
    if (z.startsWith('<![CDATA[')) {
      s.at(-1).t += z;
      continue;
    }
    if (z.startsWith('</')) {
      if (s.length === 1 || tn(z) !== s.at(-1).n) throw Error('malformed_xml');
      s.pop();
      continue;
    }
    if (z.startsWith('<!')) throw Error('invalid_cap');
    const n = tn(z),
      q = { n, c: [], t: '' };
    if (!/^[a-z_][\w.-]*$/.test(n)) throw Error('malformed_xml');
    s.at(-1).c.push(q);
    if (!z.endsWith('/>')) s.push(q);
  }
  if (s.length !== 1 || x.slice(p).trim()) throw Error('malformed_xml');
  return r;
}
const cs = (n, k) => n.c.filter((x) => x.n === k),
  val = (n, k, o) => {
    const x = cs(n, k)[0];
    return x
      ? dec((x.t + x.c.map((y) => y.t).join('')).trim()).slice(0, o.maxText)
      : null;
  };
const geo = (a) => {
  const p = val(a, 'polygon', D);
  if (p) {
    const v = p.split(/\s+/).map((q) => q.split(',').map(Number));
    return v.length >= 3 &&
      v.every(
        (q) =>
          q.length === 2 &&
          q.every(Number.isFinite) &&
          q[0] >= -90 &&
          q[0] <= 90 &&
          q[1] >= -180 &&
          q[1] <= 180,
      )
      ? { type: 'polygon', coordinates: v }
      : null;
  }
  const c = val(a, 'circle', D)?.split(/[ ,]+/).map(Number);
  return c?.length === 3 &&
    c.every(Number.isFinite) &&
    c[0] >= -90 &&
    c[0] <= 90 &&
    c[1] >= -180 &&
    c[1] <= 180 &&
    c[2] >= 0
    ? { type: 'circle', center: c.slice(0, 2), radiusKm: c[2] }
    : null;
};
export function parseCap(xml, opt = {}) {
  const o = { ...D, ...opt };
  if (
    typeof xml !== 'string' ||
    new TextEncoder().encode(xml).length > o.maxBytes
  )
    throw Error('invalid_cap');
  const a = cs(tree(xml, o), 'alert');
  if (!a.length || a.length > o.maxItems) throw Error('invalid_cap');
  return a.map((x) => ({
    identifier: val(x, 'identifier', o),
    sender: val(x, 'sender', o),
    sent: val(x, 'sent', o),
    msgType: val(x, 'msgtype', o),
    status: val(x, 'status', o),
    scope: val(x, 'scope', o),
    references: val(x, 'references', o),
    info: cs(x, 'info').map((i) => ({
      language: val(i, 'language', o),
      category: val(i, 'category', o),
      event: val(i, 'event', o),
      urgency: val(i, 'urgency', o),
      severity: val(i, 'severity', o),
      certainty: val(i, 'certainty', o),
      headline: val(i, 'headline', o),
      description: val(i, 'description', o),
      instruction: val(i, 'instruction', o),
      onset: val(i, 'onset', o),
      expires: val(i, 'expires', o),
      areas: cs(i, 'area').map((a) => ({
        description: val(a, 'areadesc', o),
        geometry: geo(a),
        geocode: val(a, 'value', o),
      })),
    })),
  }));
}
// NWS serves the same CAP fields as GeoJSON in one response
// (https://www.weather.gov/documentation/services-web-api), so the whole
// active set arrives without one CAP document fetch per alert.
const ringGeometry = (ring) => {
  if (!Array.isArray(ring) || ring.length < 3) return null;
  const v = ring.map((p) => (Array.isArray(p) ? [p[1], p[0]] : []));
  return v.every(
    (q) =>
      q.length === 2 &&
      q.every(Number.isFinite) &&
      q[0] >= -90 &&
      q[0] <= 90 &&
      q[1] >= -180 &&
      q[1] <= 180,
  )
    ? { type: 'polygon', coordinates: v }
    : null;
};
const nwsGeometry = (g) =>
  ringGeometry(g?.type === 'Polygon' ? g.coordinates?.[0] : null);
const str = (x, o) => (typeof x === 'string' ? x.slice(0, o.maxText) : null);
export function parseNwsAlerts(text, opt = {}) {
  const o = { ...D, maxItems: 5000, ...opt };
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    throw Error('invalid_cap');
  }
  const features = doc?.features;
  if (!Array.isArray(features) || features.length > o.maxItems)
    throw Error('invalid_cap');
  return features.flatMap((f) => {
    const p = f?.properties;
    if (!p || typeof p.id !== 'string') return [];
    return [
      {
        identifier: p.id,
        sender: str(p.sender, o),
        sent: str(p.sent, o),
        msgType: str(p.messageType, o),
        status: str(p.status, o),
        scope: str(p.scope, o),
        references: Array.isArray(p.references)
          ? p.references
              .filter((r) => typeof r?.identifier === 'string')
              .map((r) => `${r.sender || ''},${r.identifier},${r.sent || ''}`)
              .join(' ')
          : null,
        info: [
          {
            language: str(p.language, o),
            category: str(p.category, o),
            event: str(p.event, o),
            urgency: str(p.urgency, o),
            severity: str(p.severity, o),
            certainty: str(p.certainty, o),
            headline: str(p.headline, o),
            description: str(p.description, o),
            instruction: str(p.instruction, o),
            onset: str(p.onset, o),
            expires: str(p.expires, o),
            areas: [
              {
                description: str(p.areaDesc, o),
                geometry: nwsGeometry(f.geometry),
                geocode: str(p.geocode?.UGC?.[0], o),
              },
            ],
          },
        ],
      },
    ];
  });
}

// MSC GeoMet's weather-alerts collection (OGC API Features,
// https://eccc-msc.github.io/open-data/msc-data/alerts/readme_alerts-geomet_en/)
// serves ECCC's active alerts as one feature per alert area. A feature id is
// `<alert id>_<feature_id>`; the alert id is the one each CAP-CP message
// carries in its layer:EC-MSC-SMC:1.1:Parent_URI parameter and stays the same
// across that alert's CAP Updates, so features are grouped back into one
// alert per id. The CAP identifier itself (urn:oid:2.49.0.1.124...) changes
// with every message and is not in the collection.
//
// status_en is per area: issued, continued, changed_from (fr: "remplace":
// this alert replaces an earlier one on that area) are active; ended areas are
// dropped, and an alert whose areas have all ended is passed on as a Cancel so
// the lifecycle state stops serving it before its expires.
//
// GeoMet has no CAP severity/urgency/certainty. Severity follows the alert
// colour (ECCC colour-coded alerts: yellow moderate, orange major, red
// extreme). In 31 days of ECCC's CAP on the MSC Datamart, 915 of 917 active
// yellow messages were Moderate and both red ones Extreme; no orange was
// issued. Uncoloured statements are ECCC's low-impact tier, Minor in 93 of
// 134 CAP messages (Moderate in the rest). Other uncoloured alerts are the
// marine program, which has no colours and sends Moderate or Severe: Unknown.
const ECCC_SEVERITY = { yellow: 'Moderate', orange: 'Severe', red: 'Extreme' };
const ecccTime = (x) => {
  const n = typeof x === 'string' ? Date.parse(x) : NaN;
  return Number.isFinite(n) ? n : -Infinity;
};
const ecccLatest = (features, key) =>
  features.reduce((best, f) => {
    const value = f.properties[key];
    return ecccTime(value) > ecccTime(best) ? value : best;
  }, null);
const ecccAreas = (f, name, withGeometry, o) => {
  const g = f.geometry;
  const parts =
    g?.type === 'MultiPolygon' && Array.isArray(g.coordinates)
      ? g.coordinates
      : [g?.type === 'Polygon' ? g.coordinates : null];
  return parts.map((rings) => ({
    description: str(name, o),
    geometry: withGeometry ? ringGeometry(rings?.[0]) : null,
    geocode: str(f.properties.feature_id, o),
  }));
};
export function parseEcccAlerts(text, opt = {}) {
  const o = { ...D, maxItems: 10000, ...opt };
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    throw Error('invalid_cap');
  }
  const features = doc?.features;
  if (!Array.isArray(features) || features.length > o.maxItems)
    throw Error('invalid_cap');
  const groups = new Map();
  for (const f of features) {
    const fid = f?.properties?.feature_id;
    const id = f?.id;
    if (typeof fid !== 'string' || !fid || typeof id !== 'string') continue;
    if (!id.endsWith(`_${fid}`) || id.length <= fid.length + 1) continue;
    const alertId = id.slice(0, -fid.length - 1);
    if (!groups.has(alertId)) groups.set(alertId, []);
    groups.get(alertId).push(f);
  }
  return [...groups].map(([identifier, group]) => {
    const head = {
      identifier,
      sender: null,
      // Latest change to any area, ended ones included, so an alert that
      // shrinks replaces its earlier, larger version in the state.
      sent: str(ecccLatest(group, 'publication_datetime'), o),
      msgType: 'Alert',
      // i18n-ignore: CAP status code, not UI text
      status: 'Actual',
      scope: 'Public',
      references: null,
    };
    const active = group.filter((f) => f.properties.status_en !== 'ended');
    if (!active.length) return { ...head, msgType: 'Cancel', info: [] };
    const lead = active.reduce((a, b) =>
      ecccTime(b.properties.publication_datetime) >
      ecccTime(a.properties.publication_datetime)
        ? b
        : a,
    ).properties;
    const colour = String(lead.risk_colour_en || '').toLowerCase();
    const severity =
      ECCC_SEVERITY[colour] ||
      (lead.alert_type === 'statement' ? 'Minor' : 'Unknown');
    const expires = str(ecccLatest(active, 'expiration_datetime'), o);
    const info = (lang, suffix, withGeometry) => {
      const name = lead[`alert_name_${suffix}`];
      const tint = lead[`risk_colour_${suffix}`];
      return {
        language: lang,
        category: 'Met',
        event: str(name, o),
        urgency: null,
        severity,
        certainty: null,
        headline: str(tint && name ? `${name} (${tint})` : name, o),
        description: str(lead[`alert_text_${suffix}`], o),
        instruction: null,
        onset: str(lead.validity_datetime, o),
        expires,
        areas: active.flatMap((f) =>
          ecccAreas(f, f.properties[`feature_name_${suffix}`], withGeometry, o),
        ),
      };
    };
    // ECCC's CAP-CP carries an en-CA and a fr-CA info block. Polygons are
    // attached once, to the English block, so the response is not doubled.
    return {
      ...head,
      info: [info('en-CA', 'en', true), info('fr-CA', 'fr', false)],
    };
  });
}
