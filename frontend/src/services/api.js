import axios from 'axios';

// Use /api in production (proxy), or fallback to localhost:5000 in development if env var is missing
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';

const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

api.interceptors.request.use((config) => {
    const token = localStorage.getItem('token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401 || (error.response?.status === 404 && error.response?.data?.detail === "User not found")) {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            window.location.href = '/register';
        }
        return Promise.reject(error);
    }
);

export default api;
