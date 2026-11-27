import { useEffect, useRef, useState, useCallback } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

const API = 'http://127.0.0.1:8000';
const MONO = 'JetBrains Mono, monospace';
const PANEL_BG = 'rgba(6,10,15,0.9)';

// OTX targeted countries: one colour, sized by how many pulses name the country
const MARKER = { dot: '#f97316', ring: '#f9731630', glow: '#f97316cc' };
// Asset pins: coloured by the highest severity recorded on an open incident (grey = none)
const SEVERITY_COLOR = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22d3ee' };
const NO_INCIDENT_COLOR = '#94a3b8';
const IP_COLOR = '#a855f7';
// The map wraps east-west, so draw every mark on the neighbouring copies of the world too
const WORLD_COPIES = [-360, 0, 360];
const COUNTRY_MARKERS_MAX_ZOOM = 6; // OTX only names countries; past this a centre point would look like a street

const ESRI = 'https://server.arcgisonline.com/ArcGIS/rest/services';
const tiles = (service, attribution) =>
  L.tileLayer(`${ESRI}/${service}/MapServer/tile/{z}/{y}/{x}`, { maxNativeZoom: 19, maxZoom: 19, attribution });
const IMAGERY_ATTRIBUTION = 'Tiles &copy; Esri &mdash; Source: Esri, Maxar, Earthstar Geographics, and the GIS User Community';
const STREET_ATTRIBUTION = 'Tiles &copy; Esri &mdash; Sources: Esri, HERE, Garmin, USGS, Intermap, INCREMENT P, NRCan, Esri Japan, METI, Esri China (Hong Kong), Esri Korea, Esri (Thailand), NGCC, &copy; OpenStreetMap contributors, and the GIS User Community';

const pinIcon = (color) => L.divIcon({
  className: '',
  html: `<svg width="26" height="36" viewBox="0 0 26 36" style="filter:drop-shadow(0 2px 3px rgba(0,0,0,.6))">
    <path d="M13 0C5.8 0 0 5.8 0 13c0 9.7 13 23 13 23s13-13.3 13-23C26 5.8 20.2 0 13 0z" fill="${color}" stroke="#0b1220" stroke-width="1.5"/>
    <circle cx="13" cy="13" r="5" fill="#0b1220"/></svg>`,
  iconSize: [26, 36],
  iconAnchor: [13, 36], // the tip of the pin is the exact spot
});

const countryIcon = (alertCount) => {
  const dotSize = 8 + Math.min(alertCount, 10);
  const ring = dotSize * 2.6;
  return L.divIcon({
    className: '',
    html: `<div style="position:relative;width:${ring}px;height:${ring}px;pointer-events:auto;">
      <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:${ring}px;height:${ring}px;border-radius:50%;background:${MARKER.ring};border:1px solid ${MARKER.dot}44;animation:pulse-ring 2.4s ease-out infinite;"></div>
      <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:${dotSize}px;height:${dotSize}px;border-radius:50%;background:${MARKER.dot};box-shadow:0 0 8px ${MARKER.glow},0 0 20px ${MARKER.ring};"></div>
    </div>`,
    iconSize: [ring, ring],
    iconAnchor: [ring / 2, ring / 2],
  });
};

// The side panel (320px) covers the right of the map, so aim at the middle of the part still visible
const PANEL_WIDTH = 320;
const flyBesidePanel = (map, lat, lng, zoom) => {
  if (!map) return;
  const target = map.unproject(map.project([lat, lng], zoom).add([PANEL_WIDTH / 2, 0]), zoom);
  map.flyTo(target, zoom, { duration: 1.2 });
};

const label = (text) => (
  <div style={{ fontSize: '0.6rem', color: '#64748b', fontFamily: MONO, letterSpacing: '0.12em', margin: '10px 0 4px' }}>{text}</div>
);

const AttackMap = () => {
  const mapRef     = useRef(null);
  const leafletMap = useRef(null);
  const layersRef  = useRef(null); // { countries, assets, ips } layer groups
  const placingRef = useRef(null);
  const [mapData, setMapData]     = useState(null);
  const [selection, setSelection] = useState(null); // { kind: 'country' | 'asset' | 'ip', id }
  const [latLon, setLatLon]       = useState({ lat: '0.00', lon: '0.00' });
  const [zoom, setZoom]           = useState(2);
  const [tickerIdx, setTickerIdx] = useState(0);
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

    (mapData.nodes || []).forEach(node => WORLD_COPIES.forEach(shift => {
      L.marker([node.lat, node.lng + shift], { icon: countryIcon(node.alert_count) })
        .on('click', () => {
          setSelection({ kind: 'country', id: node.country });
          if (map.getZoom() < 5) flyBesidePanel(map, node.lat, node.lng + shift, 5);
        })
        .addTo(layers.countries);
    }));

    (mapData.ip_areas || []).forEach(area => WORLD_COPIES.forEach(shift => {
      L.circle([area.lat, area.lng + shift], {
        radius: area.accuracy_km * 1000, // MaxMind's own accuracy radius
        color: IP_COLOR, weight: 1.5, fillColor: IP_COLOR, fillOpacity: 0.15, bubblingMouseEvents: false,
      }).on('click', () => setSelection({ kind: 'ip', id: area.ip })).addTo(layers.ips);
      // A small accuracy circle is sub-pixel when zoomed out; this fixed-size dot keeps it findable
      L.circleMarker([area.lat, area.lng + shift], {
        radius: 5, color: IP_COLOR, weight: 2, fillColor: IP_COLOR, fillOpacity: 0.6, bubblingMouseEvents: false,
      }).on('click', () => setSelection({ kind: 'ip', id: area.ip })).addTo(layers.ips);
    }));

    (mapData.asset_pins || []).forEach(pin => WORLD_COPIES.forEach(shift => {
      L.marker([pin.lat, pin.lng + shift], {
        icon: pinIcon(SEVERITY_COLOR[pin.highest_severity] || NO_INCIDENT_COLOR),
        zIndexOffset: 1000,
        title: pin.name,
      }).on('click', () => setSelection({ kind: 'asset', id: pin.id })).addTo(layers.assets);
    }));
  }, [mapData]);

  useEffect(() => {
    if (!mapData?.ticker?.length) return;
    const t = setInterval(() => setTickerIdx(i => (i + 1) % mapData.ticker.length), 6000);
    return () => clearInterval(t);
  }, [mapData]);

  const startPlacing = async (assetId = null) => {
    setPlaceMsg(null);
    try {
      const list = await (await fetch(`${API}/api/assets`)).json();
      setAssets(list);
      const first = assetId ?? list[0]?.id;
      if (first == null) { setPlaceMsg('No assets registered yet.'); return; }
      setPlacing({ assetId: first, label: list.find(a => a.id === first)?.location_label || '' });
    } catch {
      setPlaceMsg('Could not load assets.');
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

  const ticker      = mapData?.ticker?.length ? mapData.ticker[tickerIdx % mapData.ticker.length] : '';
  const tickerColor = ticker.startsWith('[RED]') ? '#ef4444' : ticker.startsWith('[ORANGE]') ? '#f97316' : '#94a3b8';
  const tickerText  = ticker.replace(/^\[(RED|ORANGE|WHITE)\]\s*/, ''); // the tag only picks the colour
  const summary = mapData?.summary || {};
  const nothingPlotted = mapData && !mapData.nodes.length && !mapData.asset_pins?.length && !mapData.ip_areas?.length;

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%', background: '#060a0f', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>

      {/* Top bar */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, zIndex: 1000,
        display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '16px',
        padding: '10px 18px', background: 'linear-gradient(to bottom, rgba(6,10,15,0.97) 60%, transparent)', pointerEvents: 'none',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: '8px', height: '8px', borderRadius: '50%',
            background: loading ? '#eab308' : error ? '#ef4444' : '#22c55e',
            boxShadow: `0 0 6px ${loading ? '#eab308' : error ? '#ef4444' : '#22c55e'}`,
            animation: 'pulse-dot 2s ease-in-out infinite',
          }} />
          <span style={{ fontFamily: MONO, fontSize: '0.72rem', letterSpacing: '0.1em', color: '#cbd5e1', fontWeight: 600, whiteSpace: 'nowrap' }}>GLOBAL THREAT OPERATIONS</span>
          {loading && <span style={{ fontSize: '0.65rem', color: '#64748b', fontFamily: MONO }}>LOADING INTEL…</span>}
          {error && <span style={{ fontSize: '0.65rem', color: '#ef4444', fontFamily: MONO }}>⚠ BACKEND UNREACHABLE</span>}
          {tileError && <span style={{ fontSize: '0.65rem', color: '#eab308', fontFamily: MONO }}>⚠ MAP TILES UNAVAILABLE (needs internet) — markers still shown</span>}
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center', pointerEvents: 'auto' }}>
          {[
            { label: 'TARGETED',  value: summary.targeted_countries },
            { label: 'ACTORS',    value: summary.named_actors },
            { label: 'CVEs',      value: summary.total_cves },
            { label: 'KEV',       value: summary.kev_count },
            { label: 'OSINT',     value: summary.osint_alerts },
            { label: 'INCIDENTS', value: summary.active_incidents },
          ].map(({ label: l, value }) => (
            <div key={l} style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '0.58rem', color: '#64748b', letterSpacing: '0.1em', fontFamily: MONO }}>{l}</div>
              <div style={{ fontSize: '0.82rem', color: '#f1f5f9', fontFamily: MONO, fontWeight: 700 }}>{value ?? '—'}</div>
            </div>
          ))}
          <span style={{ fontSize: '0.65rem', color: '#94a3b8', fontFamily: MONO, marginLeft: '8px', whiteSpace: 'nowrap' }}>
            {latLon.lat}° {latLon.lon}°
          </span>
        </div>
      </div>

      {/* Place-asset toolbar */}
      <div style={{ position: 'absolute', top: '56px', left: '18px', zIndex: 1000, display: 'flex', flexDirection: 'column', gap: '6px', maxWidth: '340px' }}>
        {!placing ? (
          <button onClick={() => startPlacing()} style={toolbarButton}>⌖ Place asset on map</button>
        ) : (
          <div style={{ background: PANEL_BG, border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', padding: '10px 12px', fontSize: '0.72rem', color: '#cbd5e1' }}>
            <div style={{ marginBottom: '6px', fontWeight: 600 }}>Zoom in and click the exact spot</div>
            <select value={placing.assetId} onChange={e => {
              const id = Number(e.target.value);
              setPlacing({ assetId: id, label: assets.find(a => a.id === id)?.location_label || '' });
            }} style={field}>
              {assets.map(a => <option key={a.id} value={a.id}>{a.name}{a.latitude != null ? ' (placed)' : ''}</option>)}
            </select>
            <input value={placing.label} maxLength={200} placeholder="Label, e.g. HQ, 3rd floor (optional)"
              onChange={e => setPlacing({ ...placing, label: e.target.value })} style={{ ...field, marginTop: '6px' }} />
            <button onClick={() => { setPlacing(null); setPlaceMsg(null); }} style={{ ...toolbarButton, marginTop: '8px' }}>Cancel</button>
          </div>
        )}
        {placeMsg && <div style={{ fontSize: '0.7rem', color: '#fca5a5', background: PANEL_BG, padding: '6px 10px', borderRadius: '6px' }}>{placeMsg}</div>}
        {zoom > COUNTRY_MARKERS_MAX_ZOOM && mapData?.nodes?.length > 0 && (
          <div style={{ fontSize: '0.65rem', color: '#cbd5e1', background: PANEL_BG, padding: '6px 10px', borderRadius: '6px', fontFamily: MONO }}>
            OTX targets are published per country only — zoom out to see them
          </div>
        )}
        {mapData?.nodes?.length > 0 && mapData.unmapped_countries?.length > 0 && (
          <div style={{ fontSize: '0.62rem', color: '#cbd5e1', background: PANEL_BG, padding: '6px 10px', borderRadius: '6px', fontFamily: MONO }}>
            Not on map (no coordinates): {mapData.unmapped_countries.join(', ')}
          </div>
        )}
        {mapData && !mapData.nodes.length && !nothingPlotted && (
          <div style={{ fontSize: '0.65rem', color: '#cbd5e1', background: PANEL_BG, padding: '6px 10px', borderRadius: '6px', fontFamily: MONO }}>
            No OTX alert lists targeted countries yet
          </div>
        )}
      </div>

      {/* Map */}
      <div ref={mapRef} style={{ flex: 1, width: '100%' }} />

      {nothingPlotted && !placing && zoom <= 3 && !emptyDismissed && (
        <div style={{
          position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', zIndex: 1000,
          maxWidth: '440px', padding: '18px 22px', textAlign: 'center',
          background: 'rgba(6,10,15,0.94)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '10px',
          color: '#94a3b8', fontSize: '0.8rem', lineHeight: 1.6,
        }}>
          <button onClick={() => setEmptyDismissed(true)} aria-label="Dismiss"
            style={{ position: 'absolute', top: '6px', right: '8px', background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: '1rem' }}>×</button>
          <div style={{ color: '#e2e8f0', fontWeight: 600, marginBottom: '6px' }}>Nothing to plot yet</div>
          {summary.alerts_with_countries
            ? `${summary.alerts_with_countries} of ${summary.osint_alerts} OSINT alerts name targeted countries, but none of them could be placed on the map.`
            : `None of the ${summary.osint_alerts ?? 0} OSINT alerts lists targeted countries.`}
          {' '}No asset has been placed, and no malicious IP has a known location. Use “Place asset on map” to pin your own sites exactly; nothing is guessed.
          {mapData.unmapped_countries?.length > 0 && (
            <div style={{ marginTop: '6px' }}>Named but not mappable: {mapData.unmapped_countries.join(', ')}</div>
          )}
        </div>
      )}

      {/* Side panel, read from the latest refresh */}
      {selected && (
        <div style={{
          position: 'absolute', right: 0, top: 0, bottom: '34px', width: '320px', zIndex: 1500,
          background: 'rgba(6,10,15,0.97)', borderLeft: '1px solid rgba(255,255,255,0.07)', backdropFilter: 'blur(20px)',
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
        }}>
          <div style={{ padding: '16px 18px 12px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between' }}>
            <div>
              <div style={{ fontSize: '0.6rem', color: '#64748b', fontFamily: MONO, letterSpacing: '0.12em', marginBottom: '4px' }}>
                {selection.kind === 'country' ? 'TARGETED IN OTX PULSES' : selection.kind === 'asset' ? 'YOUR ASSET · EXACT LOCATION' : 'MALICIOUS IP · APPROXIMATE AREA'}
              </div>
              <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f1f5f9' }}>
                {selection.kind === 'country' ? selected.country : selection.kind === 'asset' ? selected.name : selected.ip}
              </div>
            </div>
            <button onClick={() => setSelection(null)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: '1.2rem', lineHeight: 1, padding: '2px 6px', alignSelf: 'flex-start' }}>×</button>
          </div>

          <div style={{ flex: 1, overflow: 'auto', padding: '12px 18px', fontSize: '0.75rem', color: '#cbd5e1', lineHeight: 1.5 }}>
            {selection.kind === 'country' && (<>
              <div style={{ display: 'flex', gap: '18px' }}>
                <Stat label="PULSES" value={selected.alert_count} />
                <Stat label="ACTORS" value={selected.actors.length} />
              </div>
              {selected.sectors?.length > 0 && (
                <div style={{ marginTop: '10px', display: 'flex', gap: '5px', flexWrap: 'wrap' }}>
                  {selected.sectors.map(s => <span key={s} style={chip('#818cf8')}>{s}</span>)}
                </div>
              )}
              {label('ADVERSARIES NAMED')}
              {selected.actors.length === 0 && <div style={{ color: '#64748b' }}>No adversary named in these pulses.</div>}
              {selected.actors.map((actor, i) => (
                <div key={i} style={card}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ fontWeight: 600, color: '#e2e8f0' }}>{actor.name}</span>
                    <span style={{ fontSize: '0.6rem', fontFamily: MONO, color: '#64748b' }}>{actor.mitre_id || ''}</span>
                  </div>
                  <div style={{ fontSize: '0.62rem', color: '#f97316' }}>
                    Named as adversary in {actor.alert_count} pulse{actor.alert_count > 1 ? 's' : ''}
                    {!actor.mitre_id && <span style={{ color: '#64748b' }}> · not an ATT&CK group name</span>}
                  </div>
                  {actor.techniques?.length > 0 && (
                    <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '4px' }}>
                      {actor.techniques.slice(0, 4).map((t, j) => <span key={j} style={chip('#94a3b8')}>{t}</span>)}
                    </div>
                  )}
                </div>
              ))}
              {label('RECENT PULSES')}
              {selected.recent_alerts.map((a, i) => (
                <div key={i} style={{ padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>{a.indicator}</div>
              ))}
            </>)}

            {selection.kind === 'asset' && (<>
              {selected.location_label && <div style={{ color: '#e2e8f0', marginBottom: '6px' }}>{selected.location_label}</div>}
              <div style={{ fontFamily: MONO, fontSize: '0.68rem', color: '#94a3b8' }}>{selected.lat.toFixed(6)}°, {selected.lng.toFixed(6)}°</div>
              <div style={{ fontSize: '0.62rem', color: '#64748b', marginTop: '2px' }}>Placed by you on this map</div>
              {label('MACHINE')}
              <div>{selected.os} · {selected.ip_address} · {selected.status}</div>
              {selected.last_seen && <div style={{ color: '#94a3b8' }}>Last seen {new Date(selected.last_seen).toLocaleString()}</div>}
              {label(`OPEN INCIDENTS (${selected.open_incidents.length})`)}
              {selected.open_incidents.length === 0 && <div style={{ color: '#64748b' }}>No open incidents on this machine.</div>}
              {selected.open_incidents.map(inc => (
                <div key={inc.id} style={card}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ fontWeight: 600, color: SEVERITY_COLOR[inc.severity] || '#e2e8f0' }}>{inc.severity} · {inc.type}</span>
                    <span style={{ fontSize: '0.6rem', fontFamily: MONO, color: '#64748b' }}>INC-{inc.id}</span>
                  </div>
                  {inc.details && <div style={{ color: '#cbd5e1' }}>{inc.details}</div>}
                  <div style={{ fontSize: '0.62rem', color: '#64748b' }}>{new Date(inc.created_at).toLocaleString()}</div>
                </div>
              ))}
              <div style={{ display: 'flex', gap: '6px', marginTop: '12px', flexWrap: 'wrap' }}>
                <button style={toolbarButton} onClick={() => zoomTo(selected.lat, selected.lng, 18)}>Zoom to building</button>
                <button style={toolbarButton} onClick={() => startPlacing(selected.id)}>Move pin</button>
                <button style={{ ...toolbarButton, color: '#fca5a5' }} onClick={() => removePin(selected.id)}>Remove pin</button>
              </div>
            </>)}

            {selection.kind === 'ip' && (<>
              <div style={{ color: '#e2e8f0' }}>{[selected.city, selected.country].filter(Boolean).join(', ') || 'Location name not in database'}</div>
              <div style={{ color: '#c4b5fd', marginTop: '4px' }}>
                Approximate: ±{selected.accuracy_km} km (GeoIP). This is where the attacker's network roughly sits, not a target.
              </div>
              {label('DETAILS')}
              {selected.detected_by && selected.detected_by !== 'AbuseIPDB' && (
                <div>Detected by: {selected.detected_by}{selected.reference ? ` (${selected.reference})` : ''}</div>
              )}
              {selected.abuse_score != null && <div>AbuseIPDB score {selected.abuse_score}/100</div>}
              {selected.machine && <div>Contacted by {selected.machine}</div>}
              <div>Source: {selected.source}</div>
              {selected.last_seen && <div style={{ color: '#94a3b8' }}>Last seen {new Date(selected.last_seen).toLocaleString()}</div>}
            </>)}
          </div>
        </div>
      )}

      {/* Legend */}
      <div style={{
        position: 'absolute', bottom: '42px', left: '18px', zIndex: 1000, maxWidth: '280px',
        background: PANEL_BG, padding: '10px 14px', borderRadius: '8px', backdropFilter: 'blur(10px)',
        border: '1px solid rgba(255,255,255,0.1)', display: 'flex', flexDirection: 'column', gap: '6px',
      }}>
        <LegendRow swatch={<div style={{ width: '9px', height: '9px', borderRadius: '50%', background: MARKER.dot, boxShadow: `0 0 5px ${MARKER.dot}` }} />}
          text="Targeted country (OTX) · size = pulses" />
        <LegendRow swatch={<svg width="10" height="14" viewBox="0 0 26 36"><path d="M13 0C5.8 0 0 5.8 0 13c0 9.7 13 23 13 23s13-13.3 13-23C26 5.8 20.2 0 13 0z" fill={NO_INCIDENT_COLOR} /></svg>}
          text="Your asset · exact · colour = open incident severity" />
        <LegendRow swatch={<div style={{ width: '10px', height: '10px', borderRadius: '50%', border: `1.5px solid ${IP_COLOR}`, background: `${IP_COLOR}33` }} />}
          text={mapData && !mapData.geoip_configured ? 'Malicious IP area · GeoIP not configured' : 'Malicious IP · approximate area (GeoIP)'} />
        <div style={{ marginTop: '2px', paddingTop: '6px', borderTop: '1px solid rgba(255,255,255,0.08)', fontSize: '0.58rem', color: '#64748b', fontFamily: MONO }}>
          Sources: AlienVault OTX, your asset placements, MaxMind GeoLite2; map tiles Esri
        </div>
      </div>

      {/* Zoom buttons */}
      <div style={{ position: 'absolute', right: selected ? '336px' : '18px', bottom: '58px', zIndex: 1000, display: 'flex', flexDirection: 'column', gap: '4px', transition: 'right 0.2s' }}>
        {['+', '−'].map((lbl, i) => (
          <button key={i}
            onClick={() => leafletMap.current && (i === 0 ? leafletMap.current.zoomIn() : leafletMap.current.zoomOut())}
            style={{
              width: '32px', height: '32px', background: PANEL_BG, border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px',
              color: '#e2e8f0', fontSize: '1.1rem', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}
          >{lbl}</button>
        ))}
      </div>

      {/* Live ticker: real OSINT alert titles */}
      <div style={{
        position: 'absolute', bottom: 0, left: 0, right: selected ? '320px' : 0, zIndex: 1000,
        background: 'rgba(6,10,15,0.95)', borderTop: '1px solid rgba(255,255,255,0.06)',
        padding: '6px 18px', display: 'flex', alignItems: 'center', gap: '14px', transition: 'right 0.2s',
      }}>
        <span style={{ fontFamily: MONO, fontSize: '0.65rem', fontWeight: 700, color: '#22c55e', letterSpacing: '0.12em', flexShrink: 0 }}>● LIVE</span>
        <span style={{ fontFamily: MONO, fontSize: '0.7rem', color: tickerColor, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{tickerText}</span>
      </div>

      <style>{`
        .leaflet-container { background: #060a0f !important; font-family: inherit; }
        .leaflet-top { top: 50px; }
        .leaflet-bottom { bottom: 30px; }
        .leaflet-control-layers { background: ${PANEL_BG}; color: #e2e8f0; border: 1px solid rgba(255,255,255,0.15) !important; border-radius: 8px; font-size: 0.72rem; }
        .leaflet-control-attribution { background: rgba(6,10,15,0.75) !important; color: #94a3b8; font-size: 0.55rem; max-width: 45vw; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .leaflet-control-attribution:hover { white-space: normal; }
        .leaflet-control-attribution a { color: #cbd5e1; }
        @keyframes pulse-ring {
          0%   { transform: translate(-50%,-50%) scale(0.7); opacity: 0.9; }
          100% { transform: translate(-50%,-50%) scale(2.2); opacity: 0; }
        }
        @keyframes pulse-dot { 0%,100% { opacity:1; } 50% { opacity:0.3; } }
      `}</style>
    </div>
  );
};

const toolbarButton = {
  background: PANEL_BG, border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', color: '#e2e8f0',
  padding: '5px 10px', fontSize: '0.7rem', cursor: 'pointer', fontFamily: MONO, alignSelf: 'flex-start',
};
const field = {
  width: '100%', background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '4px',
  color: '#e2e8f0', padding: '4px 6px', fontSize: '0.72rem', boxSizing: 'border-box',
};
const card = { padding: '8px 10px', marginTop: '6px', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: '8px' };
const chip = (color) => ({ fontSize: '0.6rem', padding: '1px 6px', borderRadius: '6px', color, background: `${color}1a`, border: `1px solid ${color}33` });

const Stat = ({ label: l, value }) => (
  <div>
    <div style={{ fontSize: '0.58rem', color: '#64748b', fontFamily: MONO }}>{l}</div>
    <div style={{ fontSize: '1rem', fontWeight: 700, color: '#f1f5f9', fontFamily: MONO }}>{value}</div>
  </div>
);
const LegendRow = ({ swatch, text }) => (
  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
    <div style={{ width: '12px', display: 'flex', justifyContent: 'center' }}>{swatch}</div>
    <span style={{ fontFamily: MONO, fontSize: '0.62rem', color: '#cbd5e1' }}>{text}</span>
  </div>
);

export default AttackMap;
