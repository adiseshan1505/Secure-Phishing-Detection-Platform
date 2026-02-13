import React from 'react';
import { detectionService } from '../services';
import Card from '../components/Card';
import Button from '../components/Button';
import AlertBox from '../components/AlertBox';
import './AnalysisPage.css';

function AnalysisPage() {
    const [url, setUrl] = React.useState('');
    const [emailContent, setEmailContent] = React.useState('');
    const [loading, setLoading] = React.useState(false);
    const [success, setSuccess] = React.useState(null);
    const [error, setError] = React.useState('');
    const [activeTab, setActiveTab] = React.useState('url');

    const handleAnalyze = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess(null);

        if (!url.trim()) {
            setError('Please enter a URL');
            return;
        }

        setLoading(true);

        try {
            const response = await detectionService.analyzeUrl(url, emailContent);
            const result = response.data.result;
            setSuccess(result);
            setUrl('');
            setEmailContent('');
        } catch (err) {
            setError(err.response?.data?.detail || 'Analysis failed');
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

                        {success && (
                            <div className={`success-banner ${success.is_phishing ? 'is-phishing' : 'is-safe'}`}>
                                <div className="success-icon">
                                    {success.is_phishing ? '🚨' : '✅'}
                                </div>
                                <div className="success-content">
                                    <h4>{success.is_phishing ? 'Phishing Detected!' : 'URL Looks Safe'}</h4>
                                    <p className="success-score">
                                        Risk Score: <strong>{success.risk_score}%</strong> | Confidence: <strong>{success.confidence}%</strong>
                                    </p>
                                    <p className="success-hint">
                                        📋 View detailed metrics and full history in the <a href="/history"><strong>History</strong></a> tab.
                                    </p>
                                </div>
                                <button className="success-close" onClick={() => setSuccess(null)}>✕</button>
                            </div>
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
            </div>
        </div>
    );
}

export default AnalysisPage;
