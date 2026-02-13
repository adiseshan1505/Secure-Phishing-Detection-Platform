import React from 'react';
import { useNavigate } from 'react-router-dom';
import { authService } from '../services';
import Button from '../components/Button';
import AlertBox from '../components/AlertBox';
import './AuthPages.css';

function LoginPage() {
    const [email, setEmail] = React.useState('');
    const [otp, setOtp] = React.useState('');
    const [loading, setLoading] = React.useState(false);
    const [error, setError] = React.useState('');
    const [success, setSuccess] = React.useState('');
    const [step, setStep] = React.useState('email'); // 'email' or 'otp'
    const [encryptionStatus, setEncryptionStatus] = React.useState(null);
    const navigate = useNavigate();

    const handleRequestOTP = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');
        setLoading(true);
        setEncryptionStatus('encrypting');

        try {
            const response = await authService.requestOTP(email);
            setEncryptionStatus('verified');
            setSuccess('✅ OTP sent to your email (AES-256 encrypted channel)');
            setTimeout(() => setStep('otp'), 1000);
        } catch (err) {
            setEncryptionStatus('failed');
            setError(err.response?.data?.error || 'Failed to request OTP');
        } finally {
            setLoading(false);
        }
    };

    const handleVerifyOTP = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');

        if (otp.length !== 6) {
            setError('Please enter 6-digit OTP');
            return;
        }

        setLoading(true);
        setEncryptionStatus('encrypting');

        try {
            const response = await authService.verifyOTPLogin(email, otp);
            setEncryptionStatus('verified');
            localStorage.setItem('token', response.data.token);
            localStorage.setItem('user', JSON.stringify(response.data.user));
            setSuccess('✅ Login successful! Credentials verified via AES-256-GCM');
            // Trigger storage event to update App authentication state
            window.dispatchEvent(new Event('storage'));
            setTimeout(() => navigate('/'), 1500);
        } catch (err) {
            setEncryptionStatus('failed');
            setError(err.response?.data?.error || 'Failed to verify OTP');
        } finally {
            setLoading(false);
        }
    };

    const renderEncryptionBadge = () => {
        if (!encryptionStatus) return null;

        const badges = {
            encrypting: {
                icon: '🔄',
                text: 'Encrypting with AES-256-GCM...',
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
                    <h1>🔐 Login</h1>
                    <p>Phishing Detection Platform</p>
                    <div className="crypto-info-bar">
                        <span className="crypto-chip">AES-256-GCM</span>
                        <span className="crypto-chip">HMAC-SHA256</span>
                        <span className="crypto-chip">E2E Encrypted</span>
                    </div>
                </div>

                {renderEncryptionBadge()}

                {step === 'email' ? (
                    // Step 1: Email Input
                    <form onSubmit={handleRequestOTP} className="auth-form">
                        {error && (
                            <AlertBox
                                type="danger"
                                title="Error"
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
                            <label htmlFor="email">📧 Email Address</label>
                            <input
                                type="email"
                                id="email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                placeholder="your-email@example.com"
                                required
                            />
                        </div>

                        <Button type="submit" disabled={loading}>
                            {loading ? '🔄 Encrypting & Sending...' : '🔒 Send OTP (Encrypted)'}
                        </Button>
                    </form>
                ) : (
                    // Step 2: OTP Verification
                    <form onSubmit={handleVerifyOTP} className="auth-form">
                        {error && (
                            <AlertBox
                                type="danger"
                                title="Verification Failed"
                                message={error}
                                onClose={() => setError('')}
                            />
                        )}

                        <div style={{
                            backgroundColor: '#e8f4f8',
                            padding: '1rem',
                            borderRadius: '4px',
                            marginBottom: '1.5rem',
                            borderLeft: '4px solid #667eea'
                        }}>
                            <p style={{ margin: '0 0 0.5rem 0', color: '#333', fontWeight: 'bold' }}>
                                📧 Email: {email}
                            </p>
                            <p style={{ margin: '0 0 0.5rem 0', color: '#666', fontSize: '0.9rem' }}>
                                ⏱️ Check your inbox for the 6-digit OTP
                            </p>
                            <p style={{ margin: 0, color: '#666', fontSize: '0.9rem' }}>
                                Valid for 5 minutes only
                            </p>
                        </div>

                        <div className="form-group">
                            <label htmlFor="otp">Enter 6-Digit OTP</label>
                            <input
                                type="text"
                                id="otp"
                                value={otp}
                                onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                placeholder="000000"
                                maxLength="6"
                                required
                                style={{ fontSize: '1.5rem', letterSpacing: '0.5rem', textAlign: 'center' }}
                            />
                        </div>

                        <Button type="submit" disabled={loading || otp.length !== 6}>
                            {loading ? '🔄 Verifying (Encrypted)...' : '🔒 Verify OTP'}
                        </Button>

                        <button
                            type="button"
                            onClick={() => {
                                setStep('email');
                                setOtp('');
                                setError('');
                                setEncryptionStatus(null);
                            }}
                            style={{
                                background: 'none',
                                border: 'none',
                                color: '#667eea',
                                cursor: 'pointer',
                                marginTop: '1rem',
                                fontSize: '0.9rem',
                                width: '100%',
                                padding: '0.5rem'
                            }}
                        >
                            ← Back to email
                        </button>
                    </form>
                )}

                <div className="auth-footer">
                    <p>
                        Don't have an account?{' '}
                        <a onClick={() => navigate('/register')}>Sign up here</a>
                    </p>
                </div>
            </div>
        </div>
    );
}

export default LoginPage;
