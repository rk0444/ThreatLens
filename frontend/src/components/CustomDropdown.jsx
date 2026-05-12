import { useState, useRef, useEffect } from 'react';
import { ChevronDown } from 'lucide-react';

export default function CustomDropdown({ options, value, onChange, placeholder = "Select..." }) {
  const [isOpen, setIsOpen] = useState(false);
  const containerRef = useRef(null);
  const [listDirection, setListDirection] = useState('down');

  const selectedOption = options.find(opt => opt.value === value);

  useEffect(() => {
    function handleClickOutside(event) {
      if (containerRef.current && !containerRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  useEffect(() => {
    if (isOpen && containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      const spaceBelow = window.innerHeight - rect.bottom;
      if (spaceBelow < 200) {
        setListDirection('up');
      } else {
        setListDirection('down');
      }
    }
  }, [isOpen]);

  const handleSelect = (option) => {
    onChange(option.value);
    setIsOpen(false);
  };

  return (
    <div ref={containerRef} style={{ position: 'relative', minWidth: '160px', width: 'auto', zIndex: isOpen ? 1001 : 1 }}>
      <div 
        onClick={() => setIsOpen(!isOpen)}
        style={{
          background: '#112240',
          border: '1px solid rgba(184, 146, 42, 0.4)',
          borderRadius: '6px',
          padding: '8px 32px 8px 12px',
          color: '#F0F4F8',
          fontSize: '14px',
          fontFamily: 'DM Sans, sans-serif',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          userSelect: 'none',
          transition: 'all 0.2s'
        }}
      >
        <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {selectedOption ? selectedOption.label : placeholder}
        </span>
        <ChevronDown 
          size={16} 
          color="#B8922A" 
          style={{ 
            position: 'absolute', 
            right: '12px', 
            transition: 'transform 0.2s',
            transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)'
          }} 
        />
      </div>

      {isOpen && (
        <div style={{
          position: 'absolute',
          left: 0,
          right: 0,
          bottom: listDirection === 'up' ? 'calc(100% + 4px)' : 'auto',
          top: listDirection === 'down' ? 'calc(100% + 4px)' : 'auto',
          background: '#1B2E4B',
          border: '1px solid rgba(184, 146, 42, 0.4)',
          borderRadius: '6px',
          boxShadow: '0 8px 24px rgba(0, 0, 0, 0.4)',
          zIndex: 1000,
          overflow: 'hidden',
          padding: '4px 0',
          maxHeight: '300px',
          overflowY: 'auto'
        }}>
          {options.map((option) => {
            const isSelected = option.value === value;
            return (
              <div
                key={option.value}
                onClick={() => handleSelect(option)}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = 'rgba(184, 146, 42, 0.15)';
                  e.currentTarget.style.color = '#D4A843';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = isSelected ? 'rgba(184, 146, 42, 0.25)' : 'transparent';
                  e.currentTarget.style.color = isSelected ? '#B8922A' : '#F0F4F8';
                }}
                style={{
                  padding: '10px 16px',
                  fontSize: '14px',
                  fontFamily: 'DM Sans, sans-serif',
                  cursor: 'pointer',
                  color: isSelected ? '#B8922A' : '#F0F4F8',
                  background: isSelected ? 'rgba(184, 146, 42, 0.25)' : 'transparent',
                  fontWeight: isSelected ? 600 : 400,
                  transition: 'all 0.1s'
                }}
              >
                {option.label}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
