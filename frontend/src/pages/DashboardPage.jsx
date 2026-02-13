import React from 'react';
import { dashboardService } from '../services';
import Card from '../components/Card';
import './DashboardPage.css';

function DashboardPage() {
    const [stats, setStats] = React.useState(null);
    const [recent, setRecent] = React.useState([]);
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState('');

    React.useEffect(() => {
        fetchData();
    }, []);

    const fetchData = async () => {
        try {
            const [statsRes, recentRes] = await Promise.all([
                dashboardService.getStats(),
                dashboardService.getRecent(5),
            ]);
            setStats(statsRes.data);
            setRecent(recentRes.data.results);
        } catch (err) {
            setError('Failed to load dashboard data');
        } finally {
            setLoading(false);
        }
    };

    if (loading) return <div className="dashboard-loading">Loading...</div>;

    return (
        <div className="dashboard-page">
            <h2>Dashboard</h2>

            {error && <div className="error-message">{error}</div>}

            {stats && (
                <>
                    <div className="stats-grid">
                        <Card className="stat-card">
                            <div className="stat-icon">📊</div>
                            <div className="stat-value">{stats.total_analyses}</div>
                            <div className="stat-label">Total Analyses</div>
                        </Card>

                        <Card className="stat-card">
                            <div className="stat-icon">🚨</div>
                            <div className="stat-value">{stats.phishing_detected}</div>
                            <div className="stat-label">Phishing Detected</div>
                        </Card>

                        <Card className="stat-card">
                            <div className="stat-icon">✅</div>
                            <div className="stat-value">{stats.legitimate_urls}</div>
                            <div className="stat-label">Legitimate URLs</div>
                        </Card>

                        <Card className="stat-card">
                            <div className="stat-icon">📈</div>
                            <div className="stat-value">{stats.detection_rate.toFixed(1)}%</div>
                            <div className="stat-label">Detection Rate</div>
                        </Card>
                    </div>

                    <div className="dashboard-grid">
                        <Card title="Risk Distribution">
                            <div className="risk-distribution">
                                <div className="distribution-item">
                                    <span className="distribution-label">
                                        <span className="risk-dot high">●</span> High Risk (75+)
                                    </span>
                                    <span className="distribution-value">{stats.risk_distribution.high}</span>
                                </div>
                                <div className="distribution-item">
                                    <span className="distribution-label">
                                        <span className="risk-dot medium">●</span> Medium Risk (50-75)
                                    </span>
                                    <span className="distribution-value">{stats.risk_distribution.medium}</span>
                                </div>
                                <div className="distribution-item">
                                    <span className="distribution-label">
                                        <span className="risk-dot low">●</span> Low Risk (&lt;50)
                                    </span>
                                    <span className="distribution-value">{stats.risk_distribution.low}</span>
                                </div>
                            </div>
                        </Card>

                        <Card title="Recent Analyses">
                            {recent.length === 0 ? (
                                <p className="empty-state">No analyses yet</p>
                            ) : (
                                <div className="recent-list">
                                    {recent.map((result) => (
                                        <div key={result.id} className="recent-item">
                                            <div className="recent-url">{result.url.substring(0, 50)}...</div>
                                            <div className="recent-status">
                                                {result.is_phishing ? '🚨 Phishing' : '✅ Safe'}
                                            </div>
                                            <div className="recent-score">{result.risk_score.toFixed(1)}%</div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </Card>
                    </div>
                </>
            )}
        </div>
    );
}

export default DashboardPage;
