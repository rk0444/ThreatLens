import { useEffect, useRef, useState, useCallback } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Crosshair, Plus, Minus, X, RotateCw } from 'lucide-react';
import { Badge, Button } from '../components/ui';

const API = 'http://127.0.0.1:8000';

// Leaflet draws with SVG attributes and HTML strings, so theme colours are read once per draw.
// shortcut: a theme switch shows on markers at the next data refresh (60 s), not instantly.
const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const markerColors = () => ({
  country: cssVar('--accent'),
  severity: { Critical: cssVar('--sev-critical'), High: cssVar('--sev-high'), Medium: cssVar('--sev-medium'), Low: cssVar('--sev-low') },
  noIncident: '#8591A0',
  ip: '#E6EAF0',     // the map is satellite imagery in both themes, so a light ring reads on it
  outline: '#0E1116',
});
// The map wraps east-west, so draw every mark on the neighbouring copies of the world too
const WORLD_COPIES = [-360, 0, 360];
const COUNTRY_MARKERS_MAX_ZOOM = 6; // OTX only names countries; past this a centre point would look like a street

const ESRI = 'https://server.arcgisonline.com/ArcGIS/rest/services';
const tiles = (service, attribution) =>
  L.tileLayer(`${ESRI}/${service}/MapServer/tile/{z}/{y}/{x}`, { maxNativeZoom: 19, maxZoom: 19, attribution });
const IMAGERY_ATTRIBUTION = 'Tiles &copy; Esri &mdash; Source: Esri, Maxar, Earthstar Geographics, and the GIS User Community';
const STREET_ATTRIBUTION = 'Tiles &copy; Esri &mdash; Sources: Esri, HERE, Garmin, USGS, Intermap, INCREMENT P, NRCan, Esri Japan, METI, Esri China (Hong Kong), Esri Korea, Esri (Thailand), NGCC, &copy; OpenStreetMap contributors, and the GIS User Community';

const PIN_PATH = 'M13 0C5.8 0 0 5.8 0 13c0 9.7 13 23 13 23s13-13.3 13-23C26 5.8 20.2 0 13 0z';
const pinIcon = (color, outline) => L.divIcon({
  className: '',
  html: `<svg width="26" height="36" viewBox="0 0 26 36"><path d="${PIN_PATH}" fill="${color}" stroke="${outline}" stroke-width="1.5"/>
    <circle cx="13" cy="13" r="5" fill="${outline}"/></svg>`,
  iconSize: [26, 36],
  iconAnchor: [13, 36], // the tip of the pin is the exact spot
});

// Size follows how many OTX pulses name the country
const countryIcon = (alertCount, color, outline) => {
  const size = 10 + Math.min(alertCount, 10) * 1.2;
  return L.divIcon({
    className: '',
    html: `<div style="width:${size}px;height:${size}px;border-radius:50%;background:${color};border:2px solid ${outline};"></div>`,
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
  });
};

// The side panel covers the right of the map, so aim at the middle of the part still visible
const PANEL_WIDTH = 320;
const flyBesidePanel = (map, lat, lng, zoom) => {
  if (!map) return;
  const target = map.unproject(map.project([lat, lng], zoom).add([PANEL_WIDTH / 2, 0]), zoom);
  map.flyTo(target, zoom, { duration: 1.2 });
};

const TICKER_SEVERITY = { RED: 'High', ORANGE: 'Medium' }; // the backend tags OSINT alerts by severity

const AttackMap = () => {
  const mapRef     = useRef(null);
  const leafletMap = useRef(null);
  const layersRef  = useRef(null); // { countries, assets, ips } layer groups
  const placingRef = useRef(null);
  const [mapData, setMapData]     = useState(null);
  const [selection, setSelection] = useState(null); // { kind: 'country' | 'asset' | 'ip', id }
  const [latLon, setLatLon]       = useState({ lat: '0.00000', lon: '0.00000' });
  const [zoom, setZoom]           = useState(2);
  const [tileError, setTileError] = useState(false);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState(null);
  const [assets, setAssets]       = useState([]);
  const [placing, setPlacing]     = useState(null); // { assetId, label } while waiting for a map click
  const [placeMsg, setPlaceMsg]   = useState(null);
  const [emptyDismissed, setEmptyDismissed] = useState(false);

  const fetchData = useCallback(() => {
    fetch(`${API}/api/attack-map`)
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(d  => { setMapData(d); setLoading(false); setError(null); })
      .catch(e => { setError(e.message); setLoading(false); });
  }, []);

  useEffect(() => {
    fetchData();
    const t = setInterval(fetchData, 60000);
    return () => clearInterval(t);
  }, [fetchData]);

  const saveLocation = useCallback(async (assetId, body) => {
    const res = await fetch(`${API}/api/assets/${assetId}/location`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Request failed (${res.status})`);
    fetchData();
  }, [fetchData]);

  // Init map: satellite with road and place labels by default, street map as the alternative
  useEffect(() => {
    if (!mapRef.current || leafletMap.current) return;
    const map = L.map(mapRef.current, {
      center: [20, 15], zoom: 2, minZoom: 2, maxZoom: 19,
      zoomControl: false, attributionControl: true, worldCopyJump: true,
      // stop at the top and bottom of the world (no black band past the poles); east-west still wraps
      maxBounds: [[-85, -1080], [85, 1080]], maxBoundsViscosity: 1.0,
    });
    const watchTiles = (layer) => layer.on('tileerror', () => setTileError(true)).on('tileload', () => setTileError(false));
    const satellite = L.layerGroup([
      watchTiles(tiles('World_Imagery', IMAGERY_ATTRIBUTION)),
      watchTiles(tiles('Reference/World_Transportation', '')),
      watchTiles(tiles('Reference/World_Boundaries_and_Places', '')),
    ]).addTo(map);
    const street = L.layerGroup([watchTiles(tiles('World_Street_Map', STREET_ATTRIBUTION))]);
    L.control.layers({ Satellite: satellite, 'Street map': street }, null, { position: 'topright', collapsed: false }).addTo(map);
    map.attributionControl.setPrefix(false);

    layersRef.current = { countries: L.layerGroup().addTo(map), assets: L.layerGroup().addTo(map), ips: L.layerGroup().addTo(map) };
    map.on('mousemove', e => setLatLon({ lat: e.latlng.lat.toFixed(5), lon: e.latlng.lng.toFixed(5) }));
    map.on('zoomend', () => setZoom(map.getZoom()));
    map.on('click', async e => {
      const p = placingRef.current;
      if (!p) { setSelection(null); return; }
      try {
        await saveLocation(p.assetId, { latitude: e.latlng.lat, longitude: e.latlng.lng, location_label: p.label || null });
        setSelection({ kind: 'asset', id: p.assetId });
        setPlaceMsg(null);
        setPlacing(null);
      } catch (err) {
        setPlaceMsg(`Could not save: ${err.message}`);
      }
    });
    leafletMap.current = map;
    // Re-measure when the container changes size (e.g. the sidebar collapses), not just on window resize
    const resize = new ResizeObserver(() => map.invalidateSize());
    resize.observe(mapRef.current);
    return () => { resize.disconnect(); map.remove(); leafletMap.current = null; layersRef.current = null; };
  }, [saveLocation]);

  useEffect(() => {
    placingRef.current = placing;
    if (leafletMap.current) leafletMap.current.getContainer().style.cursor = placing ? 'crosshair' : '';
  }, [placing]);

  // Country markers only while zoomed out far enough that a centre point reads as "this country"
  useEffect(() => {
    const map = leafletMap.current, layers = layersRef.current;
    if (!map || !layers) return;
    if (zoom > COUNTRY_MARKERS_MAX_ZOOM) map.removeLayer(layers.countries);
    else if (!map.hasLayer(layers.countries)) layers.countries.addTo(map);
  }, [zoom]);

  // Redraw everything plotted whenever the data changes
  useEffect(() => {
    const map = leafletMap.current, layers = layersRef.current;
    if (!map || !layers || !mapData) return;
    Object.values(layers).forEach(group => group.clearLayers());
    const colors = markerColors();

    (mapData.nodes || []).forEach(node => WORLD_COPIES.forEach(shift => {
      L.marker([node.lat, node.lng + shift], { icon: countryIcon(node.alert_count, colors.country, colors.outline), title: node.country, keyboard: true })
        .on('click', () => {
          setSelection({ kind: 'country', id: node.country });
          if (map.getZoom() < 5) flyBesidePanel(map, node.lat, node.lng + shift, 5);
        })
        .addTo(layers.countries);
    }));

    (mapData.ip_areas || []).forEach(area => WORLD_COPIES.forEach(shift => {
      L.circle([area.lat, area.lng + shift], {
        radius: area.accuracy_km * 1000, // MaxMind's own accuracy radius
        color: colors.ip, weight: 1.5, dashArray: '4 4', fillColor: colors.ip, fillOpacity: 0.08, bubblingMouseEvents: false,
      }).on('click', () => setSelection({ kind: 'ip', id: area.ip })).addTo(layers.ips);
      // A small accuracy circle is sub-pixel when zoomed out; this fixed-size dot keeps it findable
      L.circleMarker([area.lat, area.lng + shift], {
        radius: 5, color: colors.outline, weight: 2, fillColor: colors.ip, fillOpacity: 1, bubblingMouseEvents: false,
      }).on('click', () => setSelection({ kind: 'ip', id: area.ip })).addTo(layers.ips);
    }));

    (mapData.asset_pins || []).forEach(pin => WORLD_COPIES.forEach(shift => {
      L.marker([pin.lat, pin.lng + shift], {
        icon: pinIcon(colors.severity[pin.highest_severity] || colors.noIncident, colors.outline),
        zIndexOffset: 1000,
        title: pin.name,
      }).on('click', () => setSelection({ kind: 'asset', id: pin.id })).addTo(layers.assets);
    }));
  }, [mapData]);

  const startPlacing = async (assetId = null) => {
    setPlaceMsg(null);
    try {
      const list = await (await fetch(`${API}/api/assets`)).json();
      setAssets(list);
      const first = assetId ?? list[0]?.id;
      if (first == null) { setPlaceMsg('No endpoints registered yet.'); return; }
      setPlacing({ assetId: first, label: list.find(a => a.id === first)?.location_label || '' });
    } catch {
      setPlaceMsg('Could not load endpoints.');
    }
  };

  const removePin = async (assetId) => {
    try { await saveLocation(assetId, { latitude: null, longitude: null, location_label: null }); setSelection(null); }
    catch (err) { setPlaceMsg(`Could not remove: ${err.message}`); }
  };

  const zoomTo = (lat, lng, z) => flyBesidePanel(leafletMap.current, lat, lng, z);

  // Selection is looked up in the latest refresh, so an open panel never shows stale numbers
  const pick = (list, key) => list?.find(x => x[key] === selection?.id) || null;
  const selected = selection?.kind === 'country' ? pick(mapData?.nodes, 'country')
                 : selection?.kind === 'asset'   ? pick(mapData?.asset_pins, 'id')
                 : selection?.kind === 'ip'      ? pick(mapData?.ip_areas, 'ip')
                 : null;

  const latest = mapData?.ticker?.[0] || '';
  const latestTag = latest.match(/^\[(RED|ORANGE|WHITE)\]/)?.[1];
  const latestText = latest.replace(/^\[(RED|ORANGE|WHITE)\]\s*/, '');
  const summary = mapData?.summary || {};
  const nothingPlotted = mapData && !mapData.nodes.length && !mapData.asset_pins?.length && !mapData.ip_areas?.length;
  const stats = [
    ['Targeted countries', summary.targeted_countries], ['Named actors', summary.named_actors], ['CVEs', summary.total_cves],
    ['KEV', summary.kev_count], ['OSINT alerts', summary.osint_alerts], ['Open incidents', summary.active_incidents],
  ];

  return (
    <div className="attack-map">
      <header className="map-header">
        <div className="map-title">
          <h1>Attack Map</h1>
          <span className="small muted">
            {loading ? 'Loading map data…' : error ? `Backend unreachable (${error})` : 'Countries named in OTX pulses, your placed endpoints and located malicious IPs'}
          </span>
          {error && <Button size="sm" icon={RotateCw} onClick={fetchData}>Try again</Button>}
        </div>
        <dl className="map-stats">
          {stats.map(([l, v]) => <div key={l}><dt>{l}</dt><dd>{v ?? '–'}</dd></div>)}
        </dl>
      </header>

      <div className="map-stage">
        <div ref={mapRef} className="map-canvas" />

        {/* Place-endpoint tools and notices */}
        <div className="map-overlay map-tools">
          {!placing ? (
            <Button size="sm" icon={Crosshair} onClick={() => startPlacing()}>Place endpoint on map</Button>
          ) : (
            <div className="map-panel">
              <div style={{ fontWeight: 600, marginBottom: 'var(--s2)' }}>Zoom in and click the exact spot</div>
              <label className="field-label" htmlFor="place-asset">Endpoint</label>
              <select id="place-asset" className="input" value={placing.assetId} onChange={e => {
                const id = Number(e.target.value);
                setPlacing({ assetId: id, label: assets.find(a => a.id === id)?.location_label || '' });
              }}>
                {assets.map(a => <option key={a.id} value={a.id}>{a.name}{a.latitude != null ? ' (placed)' : ''}</option>)}
              </select>
              <label className="field-label" htmlFor="place-label" style={{ display: 'block', marginTop: 'var(--s2)' }}>Label (optional)</label>
              <input id="place-label" className="input" value={placing.label} maxLength={200} placeholder="e.g. HQ, 3rd floor"
                onChange={e => setPlacing({ ...placing, label: e.target.value })} />
              <Button size="sm" style={{ marginTop: 'var(--s3)' }} onClick={() => { setPlacing(null); setPlaceMsg(null); }}>Cancel</Button>
            </div>
          )}
          {placeMsg && <div className="map-note" role="alert">{placeMsg}</div>}
          {tileError && <div className="map-note">Map tiles are unavailable (they need internet). Markers are still shown.</div>}
          {zoom > COUNTRY_MARKERS_MAX_ZOOM && mapData?.nodes?.length > 0 && (
            <div className="map-note">OTX names targets per country only. Zoom out to see them.</div>
          )}
          {mapData?.nodes?.length > 0 && mapData.unmapped_countries?.length > 0 && (
            <div className="map-note">Not on the map (no coordinates): {mapData.unmapped_countries.join(', ')}</div>
          )}
          {mapData && !mapData.nodes.length && !nothingPlotted && (
            <div className="map-note">No OTX alert lists targeted countries yet.</div>
          )}
        </div>

        {nothingPlotted && !placing && zoom <= 3 && !emptyDismissed && (
          <div className="map-overlay map-empty map-panel" role="status">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 'var(--s2)', marginBottom: 'var(--s1)' }}>
              <strong>Nothing to plot yet</strong>
              <Button variant="ghost" size="sm" icon={X} iconOnly onClick={() => setEmptyDismissed(true)}>Dismiss</Button>
            </div>
            <p className="callout-text">
              {summary.alerts_with_countries
                ? `${summary.alerts_with_countries} of ${summary.osint_alerts} OSINT alerts name targeted countries, but none of them could be placed on the map.`
                : `None of the ${summary.osint_alerts ?? 0} OSINT alerts lists targeted countries.`}
              {' '}No endpoint has been placed, and no malicious IP has a known location. Use “Place endpoint on map” to pin your own sites exactly; nothing is guessed.
            </p>
            {mapData.unmapped_countries?.length > 0 && <p className="callout-text" style={{ marginTop: 'var(--s1)' }}>Named but not mappable: {mapData.unmapped_countries.join(', ')}</p>}
          </div>
        )}

        {/* Side panel, read from the latest refresh */}
        {selected && (
          <aside className="map-side" aria-label="Selection details">
            <div className="map-side-header">
              <div>
                <div className="small muted">
                  {selection.kind === 'country' ? 'Targeted in OTX pulses' : selection.kind === 'asset' ? 'Your endpoint · exact location' : 'Malicious IP · approximate area'}
                </div>
                <h2 className={selection.kind === 'ip' ? 'mono' : undefined}>
                  {selection.kind === 'country' ? selected.country : selection.kind === 'asset' ? selected.name : selected.ip}
                </h2>
              </div>
              <Button variant="ghost" size="sm" icon={X} iconOnly onClick={() => setSelection(null)}>Close details</Button>
            </div>

            <div className="map-side-body stack">
              {selection.kind === 'country' && (<>
                <dl className="facts">
                  <div><dt>Pulses</dt><dd>{selected.alert_count}</dd></div>
                  <div><dt>Actors named</dt><dd>{selected.actors.length}</dd></div>
                </dl>
                {selected.sectors?.length > 0 && (
                  <section>
                    <h3 className="section-title">Sectors</h3>
                    <div style={{ display: 'flex', gap: 'var(--s1)', flexWrap: 'wrap' }}>{selected.sectors.map(s => <Badge key={s}>{s}</Badge>)}</div>
                  </section>
                )}
                <section>
                  <h3 className="section-title">Adversaries named</h3>
                  {selected.actors.length === 0 && <p className="muted">No adversary named in these pulses.</p>}
                  <ul className="map-list">
                    {selected.actors.map((actor, i) => (
                      <li key={i}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 'var(--s2)' }}>
                          <strong>{actor.name}</strong>
                          {actor.mitre_id && <span className="mono small muted">{actor.mitre_id}</span>}
                        </div>
                        <div className="small muted">
                          Named as adversary in {actor.alert_count} pulse{actor.alert_count > 1 ? 's' : ''}
                          {!actor.mitre_id && ' · not an ATT&CK group name'}
                        </div>
                        {actor.techniques?.length > 0 && (
                          <div style={{ display: 'flex', gap: 'var(--s1)', flexWrap: 'wrap', marginTop: 'var(--s1)' }}>
                            {actor.techniques.slice(0, 4).map((t, j) => <Badge key={j}>{t}</Badge>)}
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                </section>
                <section>
                  <h3 className="section-title">Recent pulses</h3>
                  <ul className="map-list">{selected.recent_alerts.map((a, i) => <li key={i}>{a.indicator}</li>)}</ul>
                </section>
              </>)}

              {selection.kind === 'asset' && (<>
                <section>
                  {selected.location_label && <div>{selected.location_label}</div>}
                  <div className="mono small">{selected.lat.toFixed(6)}°, {selected.lng.toFixed(6)}°</div>
                  <div className="small muted">Placed by you on this map</div>
                </section>
                <section>
                  <h3 className="section-title">Machine</h3>
                  <div>{selected.os} · <span className="mono">{selected.ip_address}</span> · {selected.status}</div>
                  {selected.last_seen && <div className="small muted">Last seen {new Date(selected.last_seen).toLocaleString()}</div>}
                </section>
                <section>
                  <h3 className="section-title">Open incidents ({selected.open_incidents.length})</h3>
                  {selected.open_incidents.length === 0 && <p className="muted">No open incidents on this machine.</p>}
                  <ul className="map-list">
                    {selected.open_incidents.map(inc => (
                      <li key={inc.id}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 'var(--s2)', alignItems: 'center' }}>
                          <span style={{ display: 'flex', gap: 'var(--s2)', alignItems: 'center' }}><Badge severity={inc.severity} /> {inc.type}</span>
                          <span className="mono small muted">INC-{inc.id}</span>
                        </div>
                        {inc.details && <div style={{ marginTop: 2 }}>{inc.details}</div>}
                        <div className="small muted">{new Date(inc.created_at).toLocaleString()}</div>
                      </li>
                    ))}
                  </ul>
                </section>
                <div style={{ display: 'flex', gap: 'var(--s2)', flexWrap: 'wrap' }}>
                  <Button size="sm" onClick={() => zoomTo(selected.lat, selected.lng, 18)}>Zoom to building</Button>
                  <Button size="sm" onClick={() => startPlacing(selected.id)}>Move pin</Button>
                  <Button size="sm" variant="danger" onClick={() => removePin(selected.id)}>Remove pin</Button>
                </div>
              </>)}

              {selection.kind === 'ip' && (<>
                <section>
                  <div>{[selected.city, selected.country].filter(Boolean).join(', ') || 'Location name not in database'}</div>
                  <p className="small muted" style={{ marginTop: 'var(--s1)' }}>
                    Approximate: ±{selected.accuracy_km} km (GeoIP). This is roughly where the attacker's network sits, not a target.
                  </p>
                </section>
                <section>
                  <h3 className="section-title">Details</h3>
                  <dl className="facts">
                    {selected.detected_by && selected.detected_by !== 'AbuseIPDB' && (
                      <div><dt>Detected by</dt><dd style={{ fontFamily: 'var(--font-sans)', fontSize: 'var(--fs-body)' }}>{selected.detected_by}{selected.reference ? ` (${selected.reference})` : ''}</dd></div>
                    )}
                    {selected.abuse_score != null && <div><dt>AbuseIPDB score</dt><dd>{selected.abuse_score}/100</dd></div>}
                    {selected.machine && <div><dt>Contacted by</dt><dd style={{ fontFamily: 'var(--font-sans)', fontSize: 'var(--fs-body)' }}>{selected.machine}</dd></div>}
                    <div><dt>Source</dt><dd style={{ fontFamily: 'var(--font-sans)', fontSize: 'var(--fs-body)' }}>{selected.source}</dd></div>
                  </dl>
                  {selected.last_seen && <div className="small muted" style={{ marginTop: 'var(--s2)' }}>Last seen {new Date(selected.last_seen).toLocaleString()}</div>}
                </section>
              </>)}
            </div>
          </aside>
        )}

        {/* Legend: each kind has its own shape, so colour is never the only cue */}
        <div className="map-overlay map-legend map-panel">
          <div className="map-legend-row"><span className="legend-dot" aria-hidden="true" />Targeted country (OTX), size = pulses</div>
          <div className="map-legend-row">
            <svg width="10" height="14" viewBox="0 0 26 36" aria-hidden="true"><path d={PIN_PATH} fill="var(--text-3)" /></svg>
            Your endpoint, exact; colour = highest open incident severity
          </div>
          <div className="map-legend-row"><span className="legend-ring" aria-hidden="true" />
            {mapData && !mapData.geoip_configured ? 'Malicious IP area (GeoIP not configured)' : 'Malicious IP, approximate area (GeoIP)'}
          </div>
          <div className="small muted" style={{ marginTop: 'var(--s1)' }}>Sources: AlienVault OTX, your placements, MaxMind GeoLite2. Tiles: Esri.</div>
        </div>

        <div className="map-overlay map-zoom" style={{ right: selected ? PANEL_WIDTH + 16 : 16 }}>
          <Button size="sm" icon={Plus} iconOnly onClick={() => leafletMap.current?.zoomIn()}>Zoom in</Button>
          <Button size="sm" icon={Minus} iconOnly onClick={() => leafletMap.current?.zoomOut()}>Zoom out</Button>
        </div>
      </div>

      {/* Latest OSINT alert (real alert titles) and the pointer position */}
      <footer className="map-footer">
        <span className="small muted" style={{ flexShrink: 0 }}>Latest OSINT alert</span>
        {TICKER_SEVERITY[latestTag] && <Badge severity={TICKER_SEVERITY[latestTag]} />}
        <span className="map-footer-text" title={latestText}>{latestText || '–'}</span>
        <span className="mono small muted" style={{ flexShrink: 0 }}>{latLon.lat}°, {latLon.lon}°</span>
      </footer>
    </div>
  );
};

export default AttackMap;
