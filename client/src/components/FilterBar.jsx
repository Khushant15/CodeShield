import React from 'react';
import { Filter, SortAsc, SortDesc } from 'lucide-react';

export default function FilterBar({ 
  filter, 
  setFilter, 
  sort, 
  setSort, 
  counts,
  types 
}) {
  return (
    <div className="flex flex-col gap-3 p-3 rounded-xl bg-shield-surface border border-shield-border">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-[#64748b]">
          <Filter size={14} />
          <span className="text-xs font-semibold uppercase tracking-wider">Filters</span>
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={() => setSort(sort === 'severity' ? 'line' : 'severity')}
            className="flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-medium bg-shield-card border border-shield-border text-[#94a3b8] hover:text-white transition-all"
          >
            {sort === 'severity' ? <SortDescending size={12} /> : <SortAscending size={12} />}
            Sort by {sort === 'severity' ? 'Severity' : 'Line'}
          </button>
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {['All', 'Critical', 'High', 'Medium', 'Low'].map((sev) => {
          const active = filter === sev;
          const dotColors = { 
            Critical: 'bg-red-500', 
            High: 'bg-orange-500', 
            Medium: 'bg-yellow-500', 
            Low: 'bg-emerald-500', 
            All: 'bg-[#00d4ff]' 
          };
          
          return (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-medium transition-all border
                ${active 
                  ? 'bg-shield-card border-shield-border text-white shadow-lg' 
                  : 'bg-transparent border-transparent text-[#64748b] hover:text-[#94a3b8]'}`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${dotColors[sev]}`} />
              {sev}
              <span className="opacity-50 ml-0.5">{counts[sev] || 0}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function SortAscending({ size }) {
  return <SortAsc size={size} />;
}

function SortDescending({ size }) {
  return <SortDesc size={size} />;
}
