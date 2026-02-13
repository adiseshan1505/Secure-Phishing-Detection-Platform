import React from 'react';
import './RiskMeter.css';

function RiskMeter({ score, confidence }) {
    const getRiskLevel = (score) => {
        if (score >= 75) return { level: 'CRITICAL', color: '#dc2626', icon: '🔴' };
        if (score >= 50) return { level: 'HIGH', color: '#f59e0b', icon: '🟠' };
        if (score >= 25) return { level: 'MEDIUM', color: '#eab308', icon: '🟡' };
        return { level: 'LOW', color: '#10b981', icon: '🟢' };
    };

    const risk = getRiskLevel(score);

    return (
        <div className="risk-meter">
            <div className="risk-indicator" style={{ borderColor: risk.color }}>
                <div className="risk-icon">{risk.icon}</div>
                <div className="risk-info">
                    <div className="risk-level" style={{ color: risk.color }}>
                        {risk.level}
                    </div>
                    <div className="risk-score">{score.toFixed(1)}%</div>
                </div>
            </div>
            <div className="confidence-bar">
                <div className="confidence-label">Confidence</div>
                <div className="confidence-track">
                    <div
                        className="confidence-fill"
                        style={{ width: `${confidence}%` }}
                    />
                </div>
                <div className="confidence-value">{confidence.toFixed(1)}%</div>
            </div>
        </div>
    );
}

export default RiskMeter;
