import React from 'react';
import { useLocation, Link } from 'react-router-dom';
import './Sidebar.css';

function Sidebar() {
    const location = useLocation();

    const isActive = (path) => location.pathname === path;

    return (
        <aside className="sidebar">
            <nav className="sidebar-nav">
                <Link
                    to="/"
                    className={`nav-item ${isActive('/') ? 'active' : ''}`}
                >
                    📊 Dashboard
                </Link>
                <Link
                    to="/analyze"
                    className={`nav-item ${isActive('/analyze') ? 'active' : ''}`}
                >
                    🔍 Analyze URL
                </Link>
                <Link
                    to="/history"
                    className={`nav-item ${isActive('/history') ? 'active' : ''}`}
                >
                    📜 History
                </Link>
                <Link
                    to="/admin"
                    className={`nav-item ${isActive('/admin') ? 'active' : ''}`}
                >
                    ⚙️ Admin
                </Link>
            </nav>
        </aside>
    );
}

export default Sidebar;
