import React from 'react';
import { detectionService } from '../services';
import Card from '../components/Card';
import './HistoryPage.css';

function HistoryPage() {
    const [results, setResults] = React.useState([]);
    const [page, setPage] = React.useState(1);
    const [total, setTotal] = React.useState(0);
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState('');

    const perPage = 10;

    React.useEffect(() => {
        fetchHistory();
    }, [page]);

    const fetchHistory = async () => {
        setLoading(true);
        setError('');

        try {
            const response = await detectionService.getHistory(page, perPage);
            setResults(response.data.results);
            setTotal(response.data.total);
        } catch (err) {
            setError('Failed to load history');
        } finally {
            setLoading(false);
        }
    };

    const totalPages = Math.ceil(total / perPage);

    return (
        <div className="history-page">
            <h2>Analysis History</h2>

            {error && <div className="error-message">{error}</div>}

            {loading ? (
                <div className="loading">Loading history...</div>
            ) : results.length === 0 ? (
                <Card>
                    <div className="empty-state">
                        <p>📭 No analysis history yet</p>
                    </div>
                </Card>
            ) : (
                <>
                    <div className="results-table-container">
                        <table className="results-table">
                            <thead>
                                <tr>
                                    <th>URL</th>
                                    <th>Status</th>
                                    <th>Risk Score</th>
                                    <th>Confidence</th>
                                    <th>Method</th>
                                    <th>Timestamp</th>
                                </tr>
                            </thead>
                            <tbody>
                                {results.map((result) => (
                                    <tr key={result.id} className={`row-${result.is_phishing ? 'phishing' : 'safe'}`}>
                                        <td className="url-cell">
                                            <a href={result.url} target="_blank" rel="noopener noreferrer">
                                                {result.url.substring(0, 40)}...
                                            </a>
                                        </td>
                                        <td className="status-cell">
                                            {result.is_phishing ? (
                                                <span className="badge-danger">🚨 Phishing</span>
                                            ) : (
                                                <span className="badge-success">✅ Safe</span>
                                            )}
                                        </td>
                                        <td className="score-cell">{result.risk_score.toFixed(1)}%</td>
                                        <td className="confidence-cell">{result.confidence.toFixed(1)}%</td>
                                        <td className="method-cell">{result.detection_method}</td>
                                        <td className="timestamp-cell">
                                            {new Date(result.timestamp).toLocaleString()}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    <div className="pagination">
                        <button
                            onClick={() => setPage(Math.max(1, page - 1))}
                            disabled={page === 1}
                            className="pagination-btn"
                        >
                            ← Previous
                        </button>

                        <div className="page-info">
                            Page {page} of {totalPages} (Total: {total} results)
                        </div>

                        <button
                            onClick={() => setPage(Math.min(totalPages, page + 1))}
                            disabled={page === totalPages}
                            className="pagination-btn"
                        >
                            Next →
                        </button>
                    </div>
                </>
            )}
        </div>
    );
}

export default HistoryPage;
