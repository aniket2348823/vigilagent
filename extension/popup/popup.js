// Antigravity Mimic Module
// Profile Switching for IDOR Testing

// ============================================================================
// STATE
// ============================================================================

let currentTab = null;
let profiles = [];

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
    await loadCurrentTab();
    await loadProfiles();
    bindEvents();
});

async function loadCurrentTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tab;

    if (tab && tab.url) {
        try {
            const url = new URL(tab.url);
            document.getElementById('current-domain').textContent = url.hostname;

            // Count cookies for current domain
            const cookies = await chrome.cookies.getAll({ url: tab.url });
            document.getElementById('current-cookies').textContent = `${cookies.length} cookies`;
        } catch (e) {
            document.getElementById('current-domain').textContent = 'N/A';
            document.getElementById('current-cookies').textContent = 'Unable to read';
        }
    }
}

async function loadProfiles() {
    const result = await chrome.storage.local.get('mimic_profiles');
    profiles = result.mimic_profiles || [];

    document.getElementById('profile-count').textContent = profiles.length;
    renderProfiles();
}

// ============================================================================
// RENDERING
// ============================================================================

function renderProfiles() {
    const container = document.getElementById('profiles-list');

    if (profiles.length === 0) {
        container.innerHTML = '<div class="empty-state">No profiles saved yet</div>';
        return;
    }

    container.innerHTML = profiles.map((profile, index) => `
        <div class="profile-card" data-index="${index}">
            <div class="profile-info">
                <span class="profile-name">${escapeHtml(profile.name)}</span>
                <span class="profile-meta">${profile.domain} • ${profile.cookieCount} cookies</span>
            </div>
            <div class="profile-actions">
                <button class="switch-btn" data-index="${index}" title="Switch to this profile">
                    ⚡
                </button>
                <button class="delete-btn" data-index="${index}" title="Delete profile">
                    ✕
                </button>
            </div>
        </div>
    `).join('');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================================
// EVENTS
// ============================================================================

function bindEvents() {
    // Save Profile
    document.getElementById('save-profile').addEventListener('click', saveCurrentProfile);

    // Clear All
    document.getElementById('clear-all').addEventListener('click', clearAllProfiles);

    // Aegis Shield activation
    document.getElementById('activate-aegis').addEventListener('click', activateAegis);

    // Delegate clicks for profile actions
    document.getElementById('profiles-list').addEventListener('click', async (e) => {
        const target = e.target;
        const index = parseInt(target.dataset.index);

        if (target.classList.contains('switch-btn')) {
            await switchToProfile(index);
        } else if (target.classList.contains('delete-btn')) {
            await deleteProfile(index);
        }
    });
}

// ============================================================================
// PROFILE OPERATIONS
// ============================================================================

async function saveCurrentProfile() {
    if (!currentTab || !currentTab.url) {
        showNotification('No active tab', 'error');
        return;
    }

    try {
        const url = new URL(currentTab.url);
        const cookies = await chrome.cookies.getAll({ url: currentTab.url });

        const name = prompt('Enter profile name:', `Profile ${profiles.length + 1}`);
        if (!name) return;

        const profile = {
            name: name.trim(),
            domain: url.hostname,
            url: currentTab.url,
            cookies: cookies.map(c => ({
                name: c.name,
                value: c.value,
                domain: c.domain,
                path: c.path,
                secure: c.secure,
                httpOnly: c.httpOnly,
                sameSite: c.sameSite,
                expirationDate: c.expirationDate
            })),
            cookieCount: cookies.length,
            savedAt: Date.now()
        };

        profiles.push(profile);
        await chrome.storage.local.set({ mimic_profiles: profiles });

        renderProfiles();
        document.getElementById('profile-count').textContent = profiles.length;

        showNotification(`Saved "${name}"`, 'success');

    } catch (e) {
        console.error('Save error:', e);
        showNotification('Failed to save profile', 'error');
    }
}

async function switchToProfile(index) {
    const profile = profiles[index];
    if (!profile) return;

    if (!currentTab || !currentTab.url) {
        showNotification('No active tab', 'error');
        return;
    }

    try {
        // Clear existing cookies
        const existingCookies = await chrome.cookies.getAll({ url: currentTab.url });
        for (const c of existingCookies) {
            await chrome.cookies.remove({
                url: currentTab.url,
                name: c.name
            });
        }

        // Set new cookies
        for (const c of profile.cookies) {
            try {
                await chrome.cookies.set({
                    url: currentTab.url,
                    name: c.name,
                    value: c.value,
                    domain: c.domain,
                    path: c.path || '/',
                    secure: c.secure,
                    httpOnly: c.httpOnly,
                    sameSite: c.sameSite || 'lax',
                    expirationDate: c.expirationDate
                });
            } catch (cookieErr) {
                console.warn('Cookie set warning:', cookieErr);
            }
        }

        // Reload the tab
        await chrome.tabs.reload(currentTab.id);

        showNotification(`Switched to "${profile.name}"`, 'success');

        // Close popup after switch
        setTimeout(() => window.close(), 500);

    } catch (e) {
        console.error('Switch error:', e);
        showNotification('Failed to switch profile', 'error');
    }
}

async function deleteProfile(index) {
    if (!confirm('Delete this profile?')) return;

    profiles.splice(index, 1);
    await chrome.storage.local.set({ mimic_profiles: profiles });

    renderProfiles();
    document.getElementById('profile-count').textContent = profiles.length;

    showNotification('Profile deleted', 'success');
}

async function clearAllProfiles() {
    if (!confirm('Delete ALL saved profiles?')) return;

    profiles = [];
    await chrome.storage.local.set({ mimic_profiles: [] });

    renderProfiles();
    document.getElementById('profile-count').textContent = '0';

    showNotification('All profiles cleared', 'success');
}

// ============================================================================
// UI HELPERS
// ============================================================================

async function activateAegis() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) {
            showNotification('No active tab', 'error');
            return;
        }
        chrome.runtime.sendMessage({
            type: 'AEGIS_ACTIVATE',
            tab: { id: tab.id, url: tab.url }
        });
        showNotification('Aegis Shield activated!', 'success');
    } catch (e) {
        console.error('Aegis activation error:', e);
        showNotification('Failed to activate shield', 'error');
    }
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notif = document.createElement('div');
    notif.className = `notification ${type}`;
    notif.textContent = message;

    document.body.appendChild(notif);

    // Animate in
    setTimeout(() => notif.classList.add('show'), 10);

    // Remove after delay
    setTimeout(() => {
        notif.classList.remove('show');
        setTimeout(() => notif.remove(), 300);
    }, 2000);
}
