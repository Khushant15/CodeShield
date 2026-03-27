import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Filter, Search, Ban } from 'lucide-react';
import IssueCard from './IssueCard';
import FilterBar from './FilterBar';

const SEV_WEIGHTS = { Critical: 4, High: 3, Medium: 2, Low: 1 };

export default function IssueList({ issues, onLineClick }) {
  const [filter, setFilter] = useState('All');
  const [sort, setSort] = useState('severity'); // 'severity' | 'line'

  const filteredAndSorted = useMemo(() => {
    let result = [...issues];

    // Filter
    if (filter !== 'All') {
      result = result.filter(i => i.severity === filter);
    }

    // Sort
    result.sort((a, b) => {
      if (sort === 'severity') {
        const diff = SEV_WEIGHTS[b.severity] - SEV_WEIGHTS[a.severity];
        return diff !== 0 ? diff : a.line - b.line;
      } else {
        return a.line - b.line;
      }
    });

    return result;
  }, [issues, filter, sort]);

  const counts = useMemo(() => {
    return {
      All: issues.length,
      Critical: issues.filter(i => i.severity === 'Critical').length,
      High: issues.filter(i => i.severity === 'High').length,
      Medium: issues.filter(i => i.severity === 'Medium').length,
      Low: issues.filter(i => i.severity === 'Low').length,
    };
  }, [issues]);

  return (
    <div className="flex flex-col gap-4">
      <FilterBar 
        filter={filter} 
        setFilter={setFilter}
        sort={sort}
        setSort={setSort}
        counts={counts}
      />

      <div className="space-y-3">
        <AnimatePresence mode="popLayout">
          {filteredAndSorted.length > 0 ? (
            filteredAndSorted.map((issue, idx) => (
              <motion.div
                key={issue.id || idx}
                layout
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95 }}
                transition={{ duration: 0.2 }}
              >
                <IssueCard 
                  issue={issue} 
                  index={idx} 
                  onLineClick={onLineClick} 
                />
              </motion.div>
            ))
          ) : (
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex flex-col items-center justify-center py-12 px-6 rounded-xl border border-dashed border-shield-border bg-shield-surface/20 text-center"
            >
              <div className="p-3 rounded-full bg-shield-card border border-shield-border mb-3">
                <Ban size={24} className="text-slate-500" />
              </div>
              <p className="text-sm font-medium text-slate-400">No {filter !== 'All' ? filter : ''} issues found</p>
              <p className="text-xs text-slate-500 mt-1">Try adjusting your filters or scanning different code.</p>
              {filter !== 'All' && (
                <button 
                  onClick={() => setFilter('All')}
                  className="mt-4 text-xs font-semibold text-[#00d4ff] hover:underline"
                >
                  Clear filters
                </button>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
