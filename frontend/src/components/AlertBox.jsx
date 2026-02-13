import React from 'react';
import './AlertBox.css';

function AlertBox({ type = 'info', title, message, onClose }) {
    return (
        <div className={`alert alert-${type}`}>
            <div className="alert-content">
                <div className="alert-title">{title}</div>
                <div className="alert-message">{message}</div>
            </div>
            {onClose && (
                <button className="alert-close" onClick={onClose}>
                    ✕
                </button>
            )}
        </div>
    );
}

export default AlertBox;
