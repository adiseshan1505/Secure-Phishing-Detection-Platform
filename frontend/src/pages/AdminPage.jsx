import React from 'react';
import { adminService } from '../services';
import Card from '../components/Card';
import Button from '../components/Button';
import './AdminPage.css';

function AdminPage() {
    const [tab, setTab] = React.useState('statistics');
    const [stats, setStats] = React.useState(null);
    const [users, setUsers] = React.useState([]);
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState('');

    React.useEffect(() => {
        if (tab === 'statistics') {
            fetchStatistics();
        } else if (tab === 'users') {
            fetchUsers();
        }
    }, [tab]);

    const fetchStatistics = async () => {
        setLoading(true);
        setError('');

        try {
            const response = await adminService.getStatistics();
            setStats(response.data);
        } catch (err) {
            setError('Failed to load statistics');
        } finally {
            setLoading(false);
        }
    };

    const fetchUsers = async () => {
        setLoading(true);
        setError('');

        try {
            const response = await adminService.getUsers(1, 20);
            setUsers(response.data.users);
        } catch (err) {
            setError('Failed to load users');
        } finally {
            setLoading(false);
        }
    };

    const handleToggleUserStatus = async (userId) => {
        try {
            await adminService.toggleUserStatus(userId);
            fetchUsers();
        } catch (err) {
            setError('Failed to toggle user status');
        }
    };

    return (
        <div className="admin-page">
            <h2>Admin Panel</h2>

            <div className="admin-tabs">
                <button
                    className={`tab-btn ${tab === 'statistics' ? 'active' : ''}`}
                    onClick={() => setTab('statistics')}
                >
                    📊 Statistics
                </button>
                <button
                    className={`tab-btn ${tab === 'users' ? 'active' : ''}`}
                    onClick={() => setTab('users')}
                >
                    👥 Users
                </button>
            </div>

            {error && <div className="error-message">{error}</div>}

            {loading ? (
                <div className="loading">Loading...</div>
            ) : tab === 'statistics' && stats ? (
                <div className="stats-grid">
                    <Card className="admin-stat-card">
                        <div className="admin-stat-icon">👥</div>
                        <div className="admin-stat-value">{stats.users.total}</div>
                        <div className="admin-stat-label">Total Users</div>
                    </Card>

                    <Card className="admin-stat-card">
                        <div className="admin-stat-icon">✅</div>
                        <div className="admin-stat-value">{stats.users.active}</div>
                        <div className="admin-stat-label">Active Users</div>
                    </Card>

                    <Card className="admin-stat-card">
                        <div className="admin-stat-icon">🔒</div>
                        <div className="admin-stat-value">{stats.users.by_role.admin}</div>
                        <div className="admin-stat-label">Admins</div>
                    </Card>

                    <Card className="admin-stat-card">
                        <div className="admin-stat-icon">📊</div>
                        <div className="admin-stat-value">{stats.analyses.total}</div>
                        <div className="admin-stat-label">Total Analyses</div>
                    </Card>

                    <Card className="admin-stat-card">
                        <div className="admin-stat-icon">🚨</div>
                        <div className="admin-stat-value">{stats.analyses.phishing_detected}</div>
                        <div className="admin-stat-label">Phishing Detected</div>
                    </Card>

                    <Card className="admin-stat-card">
                        <div className="admin-stat-icon">📈</div>
                        <div className="admin-stat-value">{stats.analyses.detection_rate.toFixed(1)}%</div>
                        <div className="admin-stat-label">Detection Rate</div>
                    </Card>
                </div>
            ) : tab === 'users' ? (
                <Card title="Users Management">
                    <div className="users-table-container">
                        <table className="users-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Username</th>
                                    <th>Email</th>
                                    <th>Role</th>
                                    <th>Status</th>
                                    <th>Created</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {users.map((user) => (
                                    <tr key={user.id}>
                                        <td>{user.id}</td>
                                        <td>{user.username}</td>
                                        <td>{user.email}</td>
                                        <td>
                                            <span className={`role-badge role-${user.role}`}>{user.role}</span>
                                        </td>
                                        <td>
                                            {user.is_active ? (
                                                <span className="status-active">🟢 Active</span>
                                            ) : (
                                                <span className="status-inactive">🔴 Inactive</span>
                                            )}
                                        </td>
                                        <td>{new Date(user.created_at).toLocaleDateString()}</td>
                                        <td>
                                            <Button
                                                variant={user.is_active ? 'danger' : 'success'}
                                                onClick={() => handleToggleUserStatus(user.id)}
                                                className="action-btn"
                                            >
                                                {user.is_active ? 'Disable' : 'Enable'}
                                            </Button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </Card>
            ) : null}
        </div>
    );
}

export default AdminPage;
