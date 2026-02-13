import React from 'react';
import { useNavigate } from 'react-router-dom';
import { authService } from '../services';
import Button from '../components/Button';
import AlertBox from '../components/AlertBox';
import './AuthPages.css';

function RegisterPage() {
    const [formData, setFormData] = React.useState({
        username: '',
        email: '',
        phone_number: '',
        password: '',
        confirmPassword: '',
    });
    const [loading, setLoading] = React.useState(false);
    const [error, setError] = React.useState('');
    const [success, setSuccess] = React.useState('');
    const [encryptionStatus, setEncryptionStatus] = React.useState(null);
    const navigate = useNavigate();

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value,
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');

        if (formData.password !== formData.confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        setLoading(true);
        setEncryptionStatus('encrypting');

        try {
            const response = await authService.register(
                formData.username,
                formData.email,
                formData.phone_number,
                formData.password
            );
            setEncryptionStatus('verified');
            setSuccess('🔒 Registration successful! Credentials encrypted with AES-256-GCM. Redirecting to login...');
            setTimeout(() => navigate('/login'), 2500);
        } catch (err) {
            setEncryptionStatus('failed');
            setError(err.response?.data?.error || 'Registration failed');
        } finally {
            setLoading(false);
        }
    };

    const renderEncryptionBadge = () => {
        if (!encryptionStatus) return null;

        const badges = {
            encrypting: {
                icon: '🔄',
                text: 'AES-256-GCM encrypting credentials...',
                className: 'crypto-badge crypto-encrypting'
            },
            verified: {
                icon: '🔒',
                text: 'AES-256-GCM • HMAC-SHA256 Verified',
                className: 'crypto-badge crypto-verified'
            },
            failed: {
                icon: '⚠️',
                text: 'Encryption channel error',
                className: 'crypto-badge crypto-failed'
            }
        };

        const badge = badges[encryptionStatus];
        return (
            <div className={badge.className}>
                <span>{badge.icon}</span>
                <span>{badge.text}</span>
            </div>
        );
    };

    return (
        <div className="auth-container">
            <div className="auth-card">
                <div className="auth-header">
                    <h1>🔐 Create Account</h1>
                    <p>Join the Phishing Detection Platform</p>
                    <div className="crypto-info-bar">
                        <span className="crypto-chip">AES-256-GCM</span>
                        <span className="crypto-chip">PBKDF2-SHA256</span>
                        <span className="crypto-chip">RSA-2048</span>
                    </div>
                </div>

                {renderEncryptionBadge()}

                <form onSubmit={handleSubmit} className="auth-form">
                    {error && (
                        <AlertBox
                            type="danger"
                            title="Registration Error"
                            message={error}
                            onClose={() => setError('')}
                        />
                    )}

                    {success && (
                        <AlertBox
                            type="success"
                            title="Success"
                            message={success}
                        />
                    )}

                    <div className="form-group">
                        <label htmlFor="username">Username</label>
                        <input
                            type="text"
                            id="username"
                            name="username"
                            value={formData.username}
                            onChange={handleChange}
                            required
                            minLength={3}
                        />
                    </div>

                    <div className="form-group">
                        <label htmlFor="email">Email</label>
                        <input
                            type="email"
                            id="email"
                            name="email"
                            value={formData.email}
                            onChange={handleChange}
                            required
                        />
                    </div>

                    <div className="form-group">
                        <label htmlFor="phone_number">📱 Phone Number (for 2FA)</label>
                        <input
                            type="tel"
                            id="phone_number"
                            name="phone_number"
                            value={formData.phone_number}
                            onChange={handleChange}
                            placeholder="+1234567890"
                            required
                        />
                        <small>Format: +1234567890 (include country code)</small>
                    </div>

                    <div className="form-group">
                        <label htmlFor="password">🔑 Password</label>
                        <input
                            type="password"
                            id="password"
                            name="password"
                            value={formData.password}
                            onChange={handleChange}
                            required
                            minLength={8}
                        />
                        <small>Min 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char</small>
                    </div>

                    <div className="form-group">
                        <label htmlFor="confirmPassword">Confirm Password</label>
                        <input
                            type="password"
                            id="confirmPassword"
                            name="confirmPassword"
                            value={formData.confirmPassword}
                            onChange={handleChange}
                            required
                        />
                    </div>

                    <Button type="submit" disabled={loading}>
                        {loading ? '🔄 Encrypting & Registering...' : '🔒 Register (AES-256 Encrypted)'}
                    </Button>
                </form>

                <div className="crypto-footer-info">
                    <p>🛡️ Your credentials are encrypted with <strong>AES-256-GCM</strong> before transmission</p>
                    <p>Integrity verified via <strong>HMAC-SHA256</strong> • Anti-replay protection enabled</p>
                </div>

                <div className="auth-footer">
                    <p>
                        Already have an account?{' '}
                        <a onClick={() => navigate('/login')}>Login here</a>
                    </p>
                </div>
            </div>
        </div>
    );
}

export default RegisterPage;
