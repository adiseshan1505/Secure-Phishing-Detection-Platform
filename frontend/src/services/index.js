import api from './api';
import { secureRequest, encryptPayload, performHandshake } from './crypto';

export const authService = {
    register: async (username, email, phone_number, password) => {
        return await secureRequest(api, '/auth/secure-register', {
            username,
            email,
            phone_number,
            password
        });
    },

    requestOTP: async (email) => {
        const { sessionId, aesKey } = await performHandshake(api);
        const encryptedPayload = await encryptPayload({ email }, aesKey);

        const response = await api.post('/auth/secure-request-otp', {
            session_id: sessionId,
            encrypted_payload: encryptedPayload
        });

        sessionStorage.setItem('crypto_session_id', sessionId);
        sessionStorage.setItem('crypto_aes_key', aesKey);

        return response;
    },

    verifyOTPLogin: async (email, otp) => {
        const sessionId = sessionStorage.getItem('crypto_session_id');
        const aesKey = sessionStorage.getItem('crypto_aes_key');

        if (!sessionId || !aesKey) {
            return await secureRequest(api, '/auth/secure-verify-otp', {
                email,
                otp
            });
        }

        const encryptedPayload = await encryptPayload({ email, otp }, aesKey);

        const response = await api.post('/auth/secure-verify-otp', {
            session_id: sessionId,
            encrypted_payload: encryptedPayload
        });

        sessionStorage.removeItem('crypto_session_id');
        sessionStorage.removeItem('crypto_aes_key');

        return response;
    },

    login: (username, password) =>
        api.post('/auth/login', { username, password }),

    verify2FA: (userId, otp) =>
        api.post('/auth/verify-2fa', { user_id: userId, otp }),

    logout: () =>
        api.post('/auth/logout'),

    getProfile: () =>
        api.get('/auth/profile'),

    changePassword: (oldPassword, newPassword) =>
        api.post('/auth/change-password', { old_password: oldPassword, new_password: newPassword }),
};

export const detectionService = {
    analyzeUrl: (url, emailContent = '') =>
        api.post('/detection/analyze', { url, email_content: emailContent }),

    batchAnalyze: (urls) =>
        api.post('/detection/batch', { urls }),

    getHistory: (page = 1, perPage = 10) =>
        api.get(`/detection/history?page=${page}&per_page=${perPage}`),

    getResult: (resultId) =>
        api.get(`/detection/result/${resultId}`),
};

export const dashboardService = {
    getStats: () =>
        api.get('/dashboard/stats'),

    getRecent: (limit = 10) =>
        api.get(`/dashboard/recent?limit=${limit}`),

    getReport: () =>
        api.get('/dashboard/report'),
};

export const adminService = {
    getUsers: (page = 1, perPage = 10) =>
        api.get(`/admin/users?page=${page}&per_page=${perPage}`),

    getUserDetails: (userId) =>
        api.get(`/admin/users/${userId}`),

    toggleUserStatus: (userId) =>
        api.put(`/admin/users/${userId}/toggle`),

    getAuditLogs: (page = 1, perPage = 20, action = '') =>
        api.get(`/admin/audit-logs?page=${page}&per_page=${perPage}&action=${action}`),

    getStatistics: () =>
        api.get('/admin/statistics'),
};
