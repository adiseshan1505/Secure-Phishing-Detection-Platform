import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import AnalysisPage from './pages/AnalysisPage';
import HistoryPage from './pages/HistoryPage';
import AdminPage from './pages/AdminPage';
import './App.css';

function App() {
    const [isAuthenticated, setIsAuthenticated] = React.useState(
        !!localStorage.getItem('token')
    );

    React.useEffect(() => {
        // Check token on mount and when storage changes
        const checkAuth = () => {
            setIsAuthenticated(!!localStorage.getItem('token'));
        };

        window.addEventListener('storage', checkAuth);
        return () => window.removeEventListener('storage', checkAuth);
    }, []);

    const handleLoginSuccess = (token) => {
        localStorage.setItem('token', token);
        setIsAuthenticated(true);
    };

    const handleLogout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        setIsAuthenticated(false);
    };

    if (!isAuthenticated) {
        return (
            <Router>
                <Routes>
                    <Route path="/login" element={<LoginPage onLoginSuccess={handleLoginSuccess} />} />
                    <Route path="/register" element={<RegisterPage />} />
                    <Route path="*" element={<Navigate to="/login" />} />
                </Routes>
            </Router>
        );
    }

    return (
        <Router>
            <div className="app">
                <Navbar onLogout={handleLogout} />
                <div className="app-container">
                    <Sidebar />
                    <main className="main-content">
                        <Routes>
                            <Route path="/" element={<DashboardPage />} />
                            <Route path="/analyze" element={<AnalysisPage />} />
                            <Route path="/history" element={<HistoryPage />} />
                            <Route path="/admin" element={<AdminPage />} />
                            <Route path="*" element={<Navigate to="/" />} />
                        </Routes>
                    </main>
                </div>
            </div>
        </Router>
    );
}

export default App;
