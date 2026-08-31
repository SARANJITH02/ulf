import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

interface ConfidenceBadgeProps {
  confidence?: number;
  tier?: 'HIGH' | 'MEDIUM' | 'LOW';
  showPercentage?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

export const ConfidenceBadge: React.FC<ConfidenceBadgeProps> = ({
  confidence = 1.0,
  tier,
  showPercentage = true,
  size = 'md',
}) => {
  const effectiveTier = tier || (confidence >= 0.9 ? 'HIGH' : confidence >= 0.7 ? 'MEDIUM' : 'LOW');
  const percentage = Math.round(confidence * 100);

  const getStyle = () => {
    switch (effectiveTier) {
      case 'HIGH':
        return 'badge-success';
      case 'MEDIUM':
        return 'badge-warning';
      case 'LOW':
      default:
        return 'badge-danger';
    }
  };

  const getIcon = () => {
    const iconSize = size === 'sm' ? 12 : size === 'lg' ? 16 : 14;
    switch (effectiveTier) {
      case 'HIGH':
        return <ShieldCheck size={iconSize} />;
      case 'MEDIUM':
        return <AlertTriangle size={iconSize} />;
      case 'LOW':
      default:
        return <ShieldAlert size={iconSize} />;
    }
  };

  const sizeClasses = {
    sm: 'text-xs py-0.5 px-1.5',
    md: 'text-xs py-1 px-2.5',
    lg: 'text-sm py-1.5 px-3.5',
  };

  return (
    <span className={`badge ${getStyle()} ${sizeClasses[size]}`}>
      {getIcon()}
      <span>{effectiveTier}</span>
      {showPercentage && <span className="opacity-80">({percentage}%)</span>}
    </span>
  );
};
