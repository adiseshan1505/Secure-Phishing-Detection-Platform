import React from 'react';
import { useNavigate } from 'react-router-dom';
import { authService } from '../services';
import './Navbar.css';

function Navbar({ onLogout }) {
    const navigate = useNavigate();
    const [user, setUser] = React.useState(null);

    React.useEffect(() => {
        authService
            .getProfile()
            .then((res) => setUser(res.data))
            .catch(() => navigate('/login'));
    }, [navigate]);

    const handleLogout = () => {
        authService.logout();
        localStorage.removeItem('access_token');
        onLogout();
        navigate('/login');
    };

    return (
        <nav className="navbar">
            <div className="navbar-container">
                <div className="navbar-brand">
                    <h1>🔐 Phishing Detection Platform</h1>
                </div>
                <div className="navbar-items">
                    {user && <span className="user-info">👤 {user.username}</span>}
                    <button onClick={handleLogout} className="logout-btn">
                        Logout
                    </button>
                </div>
            </div>
        </nav>
    );
}

export default Navbar;
