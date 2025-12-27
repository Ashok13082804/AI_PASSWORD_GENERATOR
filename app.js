// ========================================
// USER MANAGEMENT
// ========================================

class UserManager {
    constructor() {
        this.currentUser = null;
        this.users = this.loadUsers();
    }

    loadUsers() {
        const users = localStorage.getItem('users');
        return users ? JSON.parse(users) : [];
    }

    saveUsers() {
        localStorage.setItem('users', JSON.stringify(this.users));
    }

    register(username, email, password) {
        // Validate inputs
        if (!username || !email || !password) {
            throw new Error('All fields are required');
        }

        if (password.length < 8) {
            throw new Error('Password must be at least 8 characters');
        }

        // Check if user exists
        if (this.users.find(u => u.email === email || u.username === username)) {
            throw new Error('User already exists');
        }

        // Create new user
        const user = {
            id: Date.now().toString(),
            username,
            email,
            password: this.hashPassword(password),
            createdAt: new Date().toISOString(),
            passwordHistory: []
        };

        this.users.push(user);
        this.saveUsers();
        return user;
    }

    login(identifier, password) {
        const user = this.users.find(u =>
            u.email === identifier || u.username === identifier
        );

        if (!user) {
            throw new Error('Invalid credentials');
        }

        if (user.password !== this.hashPassword(password)) {
            throw new Error('Invalid credentials');
        }

        this.currentUser = user;
        localStorage.setItem('currentUser', JSON.stringify(user));
        return user;
    }

    logout() {
        this.currentUser = null;
        localStorage.removeItem('currentUser');
    }

    getCurrentUser() {
        if (!this.currentUser) {
            const stored = localStorage.getItem('currentUser');
            if (stored) {
                this.currentUser = JSON.parse(stored);
            }
        }
        return this.currentUser;
    }

    // Simple hash function (in production, use bcrypt or similar)
    hashPassword(password) {
        let hash = 0;
        for (let i = 0; i < password.length; i++) {
            const char = password.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString(36);
    }

    addPasswordToHistory(password, strength) {
        if (!this.currentUser) return;

        const historyItem = {
            password,
            strength,
            timestamp: new Date().toISOString()
        };

        this.currentUser.passwordHistory = this.currentUser.passwordHistory || [];
        this.currentUser.passwordHistory.unshift(historyItem);

        // Keep only last 20 passwords
        if (this.currentUser.passwordHistory.length > 20) {
            this.currentUser.passwordHistory = this.currentUser.passwordHistory.slice(0, 20);
        }

        // Update in storage
        const userIndex = this.users.findIndex(u => u.id === this.currentUser.id);
        if (userIndex !== -1) {
            this.users[userIndex] = this.currentUser;
            this.saveUsers();
            localStorage.setItem('currentUser', JSON.stringify(this.currentUser));
        }
    }

    clearPasswordHistory() {
        if (!this.currentUser) return;

        this.currentUser.passwordHistory = [];

        // Update in storage
        const userIndex = this.users.findIndex(u => u.id === this.currentUser.id);
        if (userIndex !== -1) {
            this.users[userIndex] = this.currentUser;
            this.saveUsers();
            localStorage.setItem('currentUser', JSON.stringify(this.currentUser));
        }
    }

    isPasswordUnique(password) {
        if (!this.currentUser || !this.currentUser.passwordHistory) return true;
        return !this.currentUser.passwordHistory.some(item => item.password === password);
    }
}

// ========================================
// PASSWORD GENERATOR
// ========================================

class PasswordGenerator {
    constructor() {
        this.charsets = {
            uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            lowercase: 'abcdefghijklmnopqrstuvwxyz',
            numbers: '0123456789',
            special: '!@#$%^&*()-_=+[]{}|;:,.<>?',
            similar: 'O0lI1',
            memorableWords: [
                'Alpha', 'Brave', 'Cyber', 'Delta', 'Eagle', 'Frost', 'Ghost', 'Hawk',
                'Iron', 'Jade', 'Knight', 'Lotus', 'Mystic', 'Noble', 'Omega', 'Phoenix',
                'Quest', 'Razor', 'Storm', 'Tiger', 'Ultra', 'Viper', 'Wolf', 'Xenon',
                'Zenith', 'Blaze', 'Crown', 'Drake', 'Echo', 'Falcon'
            ]
        };
    }

    generate(options) {
        const {
            length = 16,
            includeUppercase = true,
            includeLowercase = true,
            includeNumbers = true,
            includeSpecial = true,
            excludeSimilar = false,
            memorableMode = false
        } = options;

        // Validate at least one character type
        if (!includeUppercase && !includeLowercase && !includeNumbers && !includeSpecial) {
            throw new Error('At least one character type must be selected');
        }

        if (memorableMode) {
            return this.generateMemorable(length, options);
        } else {
            return this.generateRandom(length, options);
        }
    }

    generateRandom(length, options) {
        let charset = '';

        if (options.includeUppercase) charset += this.charsets.uppercase;
        if (options.includeLowercase) charset += this.charsets.lowercase;
        if (options.includeNumbers) charset += this.charsets.numbers;
        if (options.includeSpecial) charset += this.charsets.special;

        // Remove similar characters if requested
        if (options.excludeSimilar) {
            charset = charset.split('').filter(char =>
                !this.charsets.similar.includes(char)
            ).join('');
        }

        let password = '';
        const array = new Uint32Array(length);
        crypto.getRandomValues(array);

        for (let i = 0; i < length; i++) {
            password += charset[array[i] % charset.length];
        }

        // Ensure at least one character from each selected type
        password = this.ensureComplexity(password, charset, options);

        return password;
    }

    generateMemorable(length, options) {
        // Generate memorable password using words + numbers + special chars
        const numWords = Math.min(3, Math.floor(length / 6));
        const words = [];

        for (let i = 0; i < numWords; i++) {
            const randomIndex = crypto.getRandomValues(new Uint32Array(1))[0]
                % this.charsets.memorableWords.length;
            words.push(this.charsets.memorableWords[randomIndex]);
        }

        let password = words.join('');

        // Add numbers and special characters to reach desired length
        const remaining = length - password.length;

        if (remaining > 0) {
            let extraChars = '';
            if (options.includeNumbers) extraChars += this.charsets.numbers;
            if (options.includeSpecial) extraChars += this.charsets.special;

            if (extraChars) {
                const array = new Uint32Array(remaining);
                crypto.getRandomValues(array);

                for (let i = 0; i < remaining; i++) {
                    password += extraChars[array[i] % extraChars.length];
                }
            }
        }

        // Trim to exact length
        return password.substring(0, length);
    }

    ensureComplexity(password, charset, options) {
        const checks = [];

        if (options.includeUppercase)
            checks.push(() => /[A-Z]/.test(password));
        if (options.includeLowercase)
            checks.push(() => /[a-z]/.test(password));
        if (options.includeNumbers)
            checks.push(() => /[0-9]/.test(password));
        if (options.includeSpecial)
            checks.push(() => /[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/.test(password));

        // If any check fails, regenerate
        if (checks.some(check => !check())) {
            return this.generateRandom(password.length, options);
        }

        return password;
    }

    calculateStrength(password) {
        let score = 0;
        let feedback = [];

        // Length score
        if (password.length >= 16) score += 25;
        else if (password.length >= 12) score += 15;
        else if (password.length >= 8) score += 10;
        else score += 5;

        // Character variety
        if (/[a-z]/.test(password)) score += 15;
        if (/[A-Z]/.test(password)) score += 15;
        if (/[0-9]/.test(password)) score += 15;
        if (/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/.test(password)) score += 20;

        // Entropy calculation
        const entropy = this.calculateEntropy(password);
        if (entropy > 80) score += 10;
        else if (entropy > 60) score += 5;

        // Determine strength level
        let strength = '';
        if (score >= 80) strength = 'Very Strong';
        else if (score >= 60) strength = 'Strong';
        else if (score >= 40) strength = 'Medium';
        else strength = 'Weak';

        return { strength, score, entropy };
    }

    calculateEntropy(password) {
        let charset = 0;
        if (/[a-z]/.test(password)) charset += 26;
        if (/[A-Z]/.test(password)) charset += 26;
        if (/[0-9]/.test(password)) charset += 10;
        if (/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/.test(password)) charset += 32;

        return Math.log2(Math.pow(charset, password.length));
    }
}

// ========================================
// UI MANAGER
// ========================================

class UIManager {
    constructor(userManager, passwordGenerator) {
        this.userManager = userManager;
        this.passwordGenerator = passwordGenerator;
        this.initializeElements();
        this.attachEventListeners();
        this.checkAuthentication();
    }

    initializeElements() {
        // Modals
        this.authModal = document.getElementById('authModal');
        this.mainApp = document.getElementById('mainApp');

        // Forms
        this.loginForm = document.getElementById('loginForm');
        this.registerForm = document.getElementById('registerForm');
        this.loginFormElement = document.getElementById('loginFormElement');
        this.registerFormElement = document.getElementById('registerFormElement');

        // Buttons
        this.showRegisterBtn = document.getElementById('showRegister');
        this.showLoginBtn = document.getElementById('showLogin');
        this.logoutBtn = document.getElementById('logoutBtn');
        this.generateBtn = document.getElementById('generateBtn');
        this.copyBtn = document.getElementById('copyBtn');
        this.clearHistoryBtn = document.getElementById('clearHistoryBtn');
        this.themeToggle = document.getElementById('themeToggle');

        // Inputs
        this.passwordLength = document.getElementById('passwordLength');
        this.lengthValue = document.getElementById('lengthValue');
        this.includeUppercase = document.getElementById('includeUppercase');
        this.includeLowercase = document.getElementById('includeLowercase');
        this.includeNumbers = document.getElementById('includeNumbers');
        this.includeSpecial = document.getElementById('includeSpecial');
        this.excludeSimilar = document.getElementById('excludeSimilar');
        this.memorableMode = document.getElementById('memorableMode');

        // Display
        this.generatedPassword = document.getElementById('generatedPassword');
        this.strengthBar = document.getElementById('strengthBar');
        this.strengthText = document.getElementById('strengthText');
        this.currentUsername = document.getElementById('currentUsername');
        this.historyList = document.getElementById('historyList');
        this.toast = document.getElementById('toast');

        // Theme
        this.moonIcon = document.querySelector('.moon-icon');
        this.sunIcon = document.querySelector('.sun-icon');

        // Initialize theme
        this.initializeTheme();
    }

    initializeTheme() {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        if (savedTheme === 'light') {
            document.body.classList.add('light-theme');
            this.updateThemeIcons(true);
        } else {
            this.updateThemeIcons(false); // Ensure dark theme icons are set if default or saved dark
        }
    }

    updateThemeIcons(isLight) {
        if (this.moonIcon && this.sunIcon) { // Check if elements exist
            if (isLight) {
                this.moonIcon.classList.add('hidden');
                this.sunIcon.classList.remove('hidden');
            } else {
                this.moonIcon.classList.remove('hidden');
                this.sunIcon.classList.add('hidden');
            }
        }
    }

    toggleTheme() {
        const isLight = document.body.classList.toggle('light-theme');
        this.updateThemeIcons(isLight);
        localStorage.setItem('theme', isLight ? 'light' : 'dark');
        this.showToast(`${isLight ? 'Light' : 'Dark'} theme activated`, 'success');
    }

    attachEventListeners() {
        // Auth
        this.showRegisterBtn.addEventListener('click', (e) => {
            e.preventDefault();
            this.showRegisterForm();
        });

        this.showLoginBtn.addEventListener('click', (e) => {
            e.preventDefault();
            this.showLoginForm();
        });

        this.loginFormElement.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        this.registerFormElement.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleRegister();
        });

        this.logoutBtn.addEventListener('click', () => this.handleLogout());

        // Theme toggle
        this.themeToggle.addEventListener('click', () => this.toggleTheme());

        // Password generation
        this.generateBtn.addEventListener('click', () => this.handleGenerate());
        this.copyBtn.addEventListener('click', () => this.handleCopy());

        // Password length slider
        this.passwordLength.addEventListener('input', (e) => {
            this.lengthValue.textContent = e.target.value;
        });

        // Clear history
        this.clearHistoryBtn.addEventListener('click', () => this.handleClearHistory());

        // Security tip action cards
        this.attachTipCardListeners();
    }

    attachTipCardListeners() {
        const tipCards = document.querySelectorAll('.tip-action-card');

        tipCards.forEach(card => {
            const actionBtn = card.querySelector('.tip-action-btn');
            if (actionBtn) {
                actionBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const action = card.dataset.action;
                    this.handleTipAction(action);
                });
            }
        });
    }

    handleTipAction(action) {
        switch (action) {
            case 'generate-unique':
                // Generate a unique, strong password with all options enabled
                this.passwordLength.value = 18;
                this.lengthValue.textContent = '18';
                this.includeUppercase.checked = true;
                this.includeLowercase.checked = true;
                this.includeNumbers.checked = true;
                this.includeSpecial.checked = true;
                this.excludeSimilar.checked = true;
                this.memorableMode.checked = false;
                this.handleGenerate();
                this.showToast('Generated unique secure password!', 'success');
                break;

            case 'set-length':
                // Set length to 20 characters for maximum security
                this.passwordLength.value = 20;
                this.lengthValue.textContent = '20';
                this.showToast('Password length set to 20 characters', 'success');
                // Scroll to generator
                document.querySelector('.generator-section').scrollIntoView({ behavior: 'smooth' });
                break;

            case 'enable-all':
                // Enable all character types for maximum complexity
                this.includeUppercase.checked = true;
                this.includeLowercase.checked = true;
                this.includeNumbers.checked = true;
                this.includeSpecial.checked = true;
                this.showToast('All character types enabled!', 'success');
                break;

            case 'copy-password':
                // Copy current password (if exists)
                this.handleCopy();
                break;

            default:
                console.warn('Unknown action:', action);
        }
    }

    checkAuthentication() {
        const user = this.userManager.getCurrentUser();
        if (user) {
            this.showMainApp(user);
        } else {
            this.showAuthModal();
        }
    }

    showAuthModal() {
        this.authModal.classList.add('active');
        this.mainApp.classList.add('hidden');
    }

    showMainApp(user) {
        this.authModal.classList.remove('active');
        this.mainApp.classList.remove('hidden');
        this.currentUsername.textContent = user.username;
        this.renderPasswordHistory();
    }

    showLoginForm() {
        this.loginForm.classList.remove('hidden');
        this.registerForm.classList.add('hidden');
    }

    showRegisterForm() {
        this.registerForm.classList.remove('hidden');
        this.loginForm.classList.add('hidden');
    }

    handleLogin() {
        const identifier = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;

        try {
            const user = this.userManager.login(identifier, password);
            this.showToast('Login successful!', 'success');
            this.showMainApp(user);
            this.loginFormElement.reset();
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    handleRegister() {
        const username = document.getElementById('registerUsername').value;
        const email = document.getElementById('registerEmail').value;
        const password = document.getElementById('registerPassword').value;
        const confirmPassword = document.getElementById('registerConfirmPassword').value;

        if (password !== confirmPassword) {
            this.showToast('Passwords do not match', 'error');
            return;
        }

        try {
            this.userManager.register(username, email, password);
            this.showToast('Registration successful! Please login.', 'success');
            this.showLoginForm();
            this.registerFormElement.reset();
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    handleLogout() {
        this.userManager.logout();
        this.showToast('Logged out successfully', 'success');
        this.showAuthModal();
        this.generatedPassword.value = '';
        this.strengthBar.style.width = '0%';
        this.strengthText.textContent = 'No password generated';
    }

    handleGenerate() {
        const options = {
            length: parseInt(this.passwordLength.value),
            includeUppercase: this.includeUppercase.checked,
            includeLowercase: this.includeLowercase.checked,
            includeNumbers: this.includeNumbers.checked,
            includeSpecial: this.includeSpecial.checked,
            excludeSimilar: this.excludeSimilar.checked,
            memorableMode: this.memorableMode.checked
        };

        try {
            let password = this.passwordGenerator.generate(options);
            let attempts = 0;
            const maxAttempts = 10;

            // Ensure unique password
            while (!this.userManager.isPasswordUnique(password) && attempts < maxAttempts) {
                password = this.passwordGenerator.generate(options);
                attempts++;
            }

            if (attempts >= maxAttempts) {
                this.showToast('Could not generate unique password. Try different options.', 'error');
                return;
            }

            const { strength, score } = this.passwordGenerator.calculateStrength(password);

            this.generatedPassword.value = password;
            this.updateStrengthMeter(strength, score);

            // Add to history
            this.userManager.addPasswordToHistory(password, strength);
            this.renderPasswordHistory();

            this.showToast('Password generated successfully!', 'success');
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    handleCopy() {
        const password = this.generatedPassword.value;

        if (!password) {
            this.showToast('No password to copy', 'error');
            return;
        }

        navigator.clipboard.writeText(password).then(() => {
            this.showToast('Password copied to clipboard!', 'success');
        }).catch(() => {
            this.showToast('Failed to copy password', 'error');
        });
    }

    handleClearHistory() {
        if (confirm('Are you sure you want to clear your password history?')) {
            this.userManager.clearPasswordHistory();
            this.renderPasswordHistory();
            this.showToast('History cleared', 'success');
        }
    }

    updateStrengthMeter(strength, score) {
        const percentage = Math.min(score, 100);
        this.strengthBar.style.width = `${percentage}%`;
        this.strengthText.textContent = `Strength: ${strength}`;

        // Remove all strength classes
        this.strengthBar.classList.remove('strength-weak', 'strength-medium', 'strength-strong', 'strength-very-strong');

        // Add appropriate class
        if (strength === 'Very Strong') {
            this.strengthBar.classList.add('strength-very-strong');
        } else if (strength === 'Strong') {
            this.strengthBar.classList.add('strength-strong');
        } else if (strength === 'Medium') {
            this.strengthBar.classList.add('strength-medium');
        } else {
            this.strengthBar.classList.add('strength-weak');
        }
    }

    renderPasswordHistory() {
        const user = this.userManager.getCurrentUser();

        if (!user || !user.passwordHistory || user.passwordHistory.length === 0) {
            this.historyList.innerHTML = '<p class="empty-state">No passwords generated yet</p>';
            return;
        }

        this.historyList.innerHTML = user.passwordHistory.map(item => {
            const date = new Date(item.timestamp);
            const timeStr = date.toLocaleString();
            const strengthClass = `strength-${item.strength.toLowerCase().replace(' ', '-')}`;

            return `
                <div class="history-item">
                    <span class="history-password">${item.password}</span>
                    <div class="history-meta">
                        <span class="history-strength ${strengthClass}">${item.strength}</span>
                        <span class="history-time">${timeStr}</span>
                    </div>
                </div>
            `;
        }).join('');
    }

    showToast(message, type = 'success') {
        this.toast.textContent = message;
        this.toast.className = `toast ${type} show`;

        setTimeout(() => {
            this.toast.classList.remove('show');
        }, 3000);
    }
}

// ========================================
// INITIALIZE APP
// ========================================

document.addEventListener('DOMContentLoaded', () => {
    const userManager = new UserManager();
    const passwordGenerator = new PasswordGenerator();
    const uiManager = new UIManager(userManager, passwordGenerator);
});
