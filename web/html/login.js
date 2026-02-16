const API_BASE = '/api';
const loginForm = document.getElementById('loginForm');
const loginError = document.getElementById('loginError');

function showError(msg) {
    loginError.textContent = msg;
    loginError.classList.add('visible');
}

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginError.classList.remove('visible');

    const formData = new FormData(loginForm);

    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: formData.get('username'),
                password: formData.get('password')
            })
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || 'Login failed');
        }

        const data = await response.json();
        localStorage.setItem('ctrltab-token', data.token);
        localStorage.setItem('ctrltab-user', JSON.stringify(data.user));
        window.location.href = '/';
    } catch (err) {
        showError(err.message);
    }
});

// If already logged in, redirect to app
(async function() {
    const token = localStorage.getItem('ctrltab-token');
    if (!token) return;

    try {
        const res = await fetch(`${API_BASE}/auth/verify`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) window.location.href = '/';
    } catch {
        // Token invalid, stay on login page
    }
})();
