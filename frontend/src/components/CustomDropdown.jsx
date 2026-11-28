// Native <select> in the design system's style: keyboard, screen readers and the OS picker come with it.
// label: visible text before the control, or hideLabel to keep it for screen readers only.
import { useId } from 'react';
import { ChevronDown } from 'lucide-react';

export default function CustomDropdown({ options, value, onChange, label, hideLabel, placeholder }) {
  const id = useId();
  return (
    <div className="select-field">
      {label && <label htmlFor={id} className={hideLabel ? 'sr-only' : 'select-label'}>{label}</label>}
      <div className="select-box">
        <select id={id} className="input select" value={value} onChange={e => onChange(e.target.value)}>
          {placeholder && value == null && <option value="" disabled>{placeholder}</option>}
          {options.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
        <ChevronDown size={14} aria-hidden="true" />
      </div>
    </div>
  );
}
