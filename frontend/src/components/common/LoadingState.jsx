import React from 'react';

const LoadingState = ({ message = 'Loading security data from API...' }) => {
  return (
    <div className="loading-state">
      <div className="spinner"></div>
      <p>{message}</p>
    </div>
  );
};

export default LoadingState;
