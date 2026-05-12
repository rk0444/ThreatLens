import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

export default function ActivityGraph({ data }) {
  return (
    <div className="glass-panel" style={{ padding: '1.5rem' }}>
      <div className="label-small" style={{ marginBottom: '0.25rem' }}>LIVE INTELLIGENCE</div>
      <div style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '1.25rem' }}>CVE Ingestion Activity — Last 24 Hours</div>
      <ResponsiveContainer width="100%" height={220}>
        <LineChart data={data} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(184,146,42,0.15)" />
          <XAxis dataKey="hour" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} interval={3} />
          <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} allowDecimals={false} />
          <Tooltip
            contentStyle={{ background: '#0d1b2a', border: '1px solid rgba(184,146,42,0.3)', borderRadius: '6px' }}
            labelStyle={{ color: 'var(--accent-gold)' }}
            itemStyle={{ color: 'var(--text-secondary)' }}
          />
          <Legend wrapperStyle={{ paddingTop: '0.75rem', fontSize: '0.8rem' }} />
          <Line type="monotone" dataKey="total" name="All CVEs" stroke="#B8922A" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
          <Line type="monotone" dataKey="critical_high" name="Critical + High" stroke="#fc8181" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
