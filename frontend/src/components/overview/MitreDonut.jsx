import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const STAGE_COLORS = {
  'Initial Access':        '#e53e3e',
  'Execution':             '#dd6b20',
  'Persistence':           '#d69e2e',
  'Privilege Escalation':  '#38a169',
  'Defense Evasion':       '#3182ce',
  'Lateral Movement':      '#805ad5',
  'Exfiltration':          '#d53f8c',
  'C2':                    '#319795',
  'Impact':                '#fc8181',
};

const RADIAN = Math.PI / 180;
const renderLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }) => {
  if (percent < 0.06) return null;
  const r = innerRadius + (outerRadius - innerRadius) * 0.5;
  return (
    <text x={cx + r * Math.cos(-midAngle * RADIAN)} y={cy + r * Math.sin(-midAngle * RADIAN)}
      fill="white" textAnchor="middle" dominantBaseline="central" fontSize={11} fontWeight={600}>
      {(percent * 100).toFixed(0)}%
    </text>
  );
};

export default function MitreDonut({ data }) {
  const total = data.reduce((s, d) => s + d.count, 0);
  return (
    <div className="glass-panel" style={{ padding: '1.5rem' }}>
      <div className="label-small" style={{ marginBottom: '0.25rem' }}>MITRE ATT&CK</div>
      <div style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '1rem' }}>Attack Stage Breakdown</div>
      <ResponsiveContainer width="100%" height={260}>
        <PieChart>
          <Pie data={data} dataKey="count" nameKey="stage" innerRadius={65} outerRadius={100}
            paddingAngle={2} labelLine={false} label={renderLabel}>
            {data.map((entry) => (
              <Cell key={entry.stage} fill={STAGE_COLORS[entry.stage] || '#666'} />
            ))}
          </Pie>
          <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central"
            fill="var(--accent-gold)" fontSize={22} fontWeight={700}>{total}</text>
          <text x="50%" y="57%" textAnchor="middle" dominantBaseline="central"
            fill="var(--text-muted)" fontSize={10}>threats</text>
          <Tooltip
            contentStyle={{ background: '#0d1b2a', border: '1px solid rgba(184,146,42,0.3)', borderRadius: '6px' }}
            itemStyle={{ color: 'var(--text-secondary)' }}
            formatter={(value, name) => [value, name]}
          />
        </PieChart>
      </ResponsiveContainer>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px 12px', marginTop: '0.5rem' }}>
        {data.map(d => (
          <div key={d.stage} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: STAGE_COLORS[d.stage] || '#666', flexShrink: 0 }} />
            {d.stage}: <strong style={{ color: 'var(--text-primary)' }}>{d.count}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}
