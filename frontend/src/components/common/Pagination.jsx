import React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';

const Pagination = ({ total, skip, limit, onPageChange }) => {
  if (!total || total <= limit) return null;

  const currentPage = Math.floor(skip / limit) + 1;
  const totalPages = Math.ceil(total / limit);

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '1rem 1.5rem', borderTop: '1px solid var(--border-color)' }}>
      <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
        Showing <span className="font-mono">{skip + 1}</span> to <span className="font-mono">{Math.min(skip + limit, total)}</span> of <span className="font-mono">{total}</span> records
      </div>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button
          className="btn btn-secondary"
          style={{ padding: '0.35rem 0.65rem' }}
          disabled={currentPage === 1}
          onClick={() => onPageChange(skip - limit)}
        >
          <ChevronLeft size={16} /> Previous
        </button>
        <span style={{ display: 'flex', alignItems: 'center', padding: '0 0.5rem', fontSize: '0.85rem' }} className="font-mono">
          Page {currentPage} of {totalPages}
        </span>
        <button
          className="btn btn-secondary"
          style={{ padding: '0.35rem 0.65rem' }}
          disabled={currentPage === totalPages}
          onClick={() => onPageChange(skip + limit)}
        >
          Next <ChevronRight size={16} />
        </button>
      </div>
    </div>
  );
};

export default Pagination;
