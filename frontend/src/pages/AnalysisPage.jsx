import React from 'react';
import { detectionService } from '../services';
import Card from '../components/Card';
import Button from '../components/Button';
import RiskMeter from '../components/RiskMeter';
import AlertBox from '../components/AlertBox';
import './AnalysisPage.css';

function AnalysisPage() {
    const [url, setUrl] = React.useState('');
    const [emailContent, setEmailContent] = React.useState('');
    const [loading, setLoading] = React.useState(false);
    const [result, setResult] = React.useState(null);
    const [error, setError] = React.useState('');
    const [activeTab, setActiveTab] = React.useState('url');

    const handleAnalyze = async (e) => {
        e.preventDefault();
        setError('');
        setResult(null);

        if (!url.trim()) {
            setError('Please enter a URL');
            return;
        }

        setLoading(true);

        try {
            const response = await detectionService.analyzeUrl(url, emailContent);
            setResult(response.data.result);
            setUrl('');
            setEmailContent('');
        } catch (err) {
            setError(err.response?.data?.error || 'Analysis failed');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="analysis-page">
            <h2>URL & Email Analysis</h2>

            <div className="analysis-grid">
                <Card title="Analyze for Phishing" className="analysis-form-card">
                    <form onSubmit={handleAnalyze} className="analysis-form">
                        {error && (
                            <AlertBox
                                type="danger"
                                title="Analysis Error"
                                message={error}
                                onClose={() => setError('')}
                            />
                        )}

                        <div className="tabs">
                            <button
                                type="button"
                                className={`tab-btn ${activeTab === 'url' ? 'active' : ''}`}
                                onClick={() => setActiveTab('url')}
                            >
                                🔗 URL Analysis
                            </button>
                            <button
                                type="button"
                                className={`tab-btn ${activeTab === 'email' ? 'active' : ''}`}
                                onClick={() => setActiveTab('email')}
                            >
                                📧 Email Analysis
                            </button>
                        </div>

                        {activeTab === 'url' && (
                            <div className="form-group">
                                <label htmlFor="url">URL to Analyze</label>
                                <input
                                    type="text"
                                    id="url"
                                    value={url}
                                    onChange={(e) => setUrl(e.target.value)}
                                    placeholder="https://example.com"
                                    required
                                />
                            </div>
                        )}

                        {activeTab === 'email' && (
                            <>
                                <div className="form-group">
                                    <label htmlFor="url">URL from Email</label>
                                    <input
                                        type="text"
                                        id="url"
                                        value={url}
                                        onChange={(e) => setUrl(e.target.value)}
                                        placeholder="https://example.com"
                                        required
                                    />
                                </div>

                                <div className="form-group">
                                    <label htmlFor="email">Email Content</label>
                                    <textarea
                                        id="email"
                                        value={emailContent}
                                        onChange={(e) => setEmailContent(e.target.value)}
                                        placeholder="Paste email content here..."
                                        rows={6}
                                    />
                                </div>
                            </>
                        )}

                        <Button type="submit" disabled={loading}>
                            {loading ? '⏳ Analyzing...' : '🔍 Analyze Now'}
                        </Button>
                    </form>
                </Card>

                {result && (
                    <Card title="Analysis Result" className="result-card">
                        <div className="result-content">
                            <RiskMeter score={result.risk_score} confidence={result.confidence} />

                            <div className="result-details">
                                <div className="detail-row">
                                    <span className="detail-label">Status:</span>
                                    <span className={`detail-value ${result.is_phishing ? 'danger' : 'success'}`}>
                                        {result.is_phishing ? '🚨 PHISHING' : '✅ SAFE'}
                                    </span>
                                </div>

                                <div className="detail-row">
                                    <span className="detail-label">Detection Method:</span>
                                    <span className="detail-value">{result.detection_method}</span>
                                </div>

                                <div className="detail-row">
                                    <span className="detail-label">Rule-based Score:</span>
                                    <span className="detail-value">{result.rule_based_score.toFixed(1)}%</span>
                                </div>

                                <div className="detail-row">
                                    <span className="detail-label">ML-based Score:</span>
                                    <span className="detail-value">{result.ml_based_score.toFixed(1)}%</span>
                                </div>

                                {result.suspicious_features && result.suspicious_features.length > 0 && (
                                    <div className="features-section">
                                        <h4>Suspicious Features Detected:</h4>
                                        <ul className="features-list">
                                            {result.suspicious_features.map((feature, idx) => (
                                                <li key={idx}>⚠️ {feature.replace(/_/g, ' ')}</li>
                                            ))}
                                        </ul>
                                    </div>
                                )}
                            </div>
                        </div>
                    </Card>
                )}
            </div>
        </div>
    );
}

export default AnalysisPage;
