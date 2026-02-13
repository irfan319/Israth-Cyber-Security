// script.js — AES-256-GCM file encryption/decryption, client-side, secure
(async function() {
    "use strict";

    // ---------- DOM bindings ----------
    const modeEncryptBtn = document.getElementById('modeEncryptBtn');
    const modeDecryptBtn = document.getElementById('modeDecryptBtn');
    const encryptBlock = document.getElementById('encryptBlock');
    const decryptBlock = document.getElementById('decryptBlock');
    
    // encryption elements
    const encryptDropZone = document.getElementById('encryptDropZone');
    const encryptFileInput = document.getElementById('encryptFileInput');
    const encryptFileName = document.getElementById('encryptFileName');
    const encryptPassword = document.getElementById('encryptPassword');
    const toggleEncryptPwd = document.getElementById('toggleEncryptPwd');
    const encryptBtn = document.getElementById('encryptBtn');
    const strengthBar = document.querySelector('#encryptStrength .strength-bar');
    
    // decryption elements
    const decryptDropZone = document.getElementById('decryptDropZone');
    const decryptFileInput = document.getElementById('decryptFileInput');
    const decryptFileName = document.getElementById('decryptFileName');
    const decryptPassword = document.getElementById('decryptPassword');
    const toggleDecryptPwd = document.getElementById('toggleDecryptPwd');
    const decryptBtn = document.getElementById('decryptBtn');
    
    // status
    const statusIcon = document.getElementById('statusIcon');
    const statusMessage = document.getElementById('statusMessage');
    const progressContainer = document.getElementById('progressContainer');
    const progressBar = document.getElementById('progressBar');

    // state
    let encryptFile = null;
    let decryptFile = null;
    let currentMode = 'encrypt'; // encrypt / decrypt

    // ---------- WebCrypto AES-GCM utils ----------
    async function getKeyMaterial(password) {
        const enc = new TextEncoder();
        return window.crypto.subtle.importKey(
            'raw',
            enc.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );
    }

    async function deriveKey(keyMaterial, salt) {
        return window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 210000,   // OWASP recommended
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    // generate random 96-bit IV (12 bytes) and 16-byte salt
    function generateIv() {
        return window.crypto.getRandomValues(new Uint8Array(12));
    }

    function generateSalt() {
        return window.crypto.getRandomValues(new Uint8Array(16));
    }

    // ---------- password strength indicator (simple) ----------
    function updateStrength(password) {
        let strength = 0;
        if (!password) { strengthBar.style.width = '0%'; return; }
        if (password.length >= 8) strength += 1;
        if (password.length >= 12) strength += 1;
        if (/[a-z]/.test(password)) strength += 0.5;
        if (/[A-Z]/.test(password)) strength += 0.5;
        if (/[0-9]/.test(password)) strength += 0.5;
        if (/[^a-zA-Z0-9]/.test(password)) strength += 1;
        strength = Math.min(strength, 5);
        const percent = (strength / 5) * 100;
        strengthBar.style.width = percent + '%';
    }

    encryptPassword.addEventListener('input', (e) => updateStrength(e.target.value));

    // ---------- toggle password visibility ----------
    function toggleVisibility(inputField, eyeSpan) {
        if (inputField.type === 'password') {
            inputField.type = 'text';
            eyeSpan.innerText = '👁️‍🗨️';
        } else {
            inputField.type = 'password';
            eyeSpan.innerText = '👁️';
        }
    }
    toggleEncryptPwd.addEventListener('click', () => toggleVisibility(encryptPassword, toggleEncryptPwd));
    toggleDecryptPwd.addEventListener('click', () => toggleVisibility(decryptPassword, toggleDecryptPwd));

    // ---------- mode toggle ----------
    function setMode(mode) {
        currentMode = mode;
        if (mode === 'encrypt') {
            modeEncryptBtn.classList.add('active');
            modeDecryptBtn.classList.remove('active');
            encryptBlock.classList.remove('hidden');
            decryptBlock.classList.add('hidden');
            resetEncryptState();
        } else {
            modeDecryptBtn.classList.add('active');
            modeEncryptBtn.classList.remove('active');
            decryptBlock.classList.remove('hidden');
            encryptBlock.classList.add('hidden');
            resetDecryptState();
        }
        setStatus('🟡', `ready · ${mode} mode`);
    }

    modeEncryptBtn.addEventListener('click', () => setMode('encrypt'));
    modeDecryptBtn.addEventListener('click', () => setMode('decrypt'));

    // ---------- reset functions ----------
    function resetEncryptState() {
        encryptFile = null;
        encryptFileName.innerText = '';
        encryptFileName.style.display = 'none';
        encryptFileInput.value = '';
        encryptPassword.value = '';
        strengthBar.style.width = '0%';
    }
    function resetDecryptState() {
        decryptFile = null;
        decryptFileName.innerText = '';
        decryptFileName.style.display = 'none';
        decryptFileInput.value = '';
        decryptPassword.value = '';
    }

    // ---------- drag & drop / file selection (encrypt) ----------
    function setupDropZone(zone, fileInput, fileNameSpan, isEncrypt) {
        zone.addEventListener('click', () => fileInput.click());

        zone.addEventListener('dragover', (e) => {
            e.preventDefault();
            zone.style.borderColor = '#0ef';
            zone.style.background = 'rgba(0,255,255,0.05)';
        });
        zone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            zone.style.borderColor = '#1f627a';
            zone.style.background = 'rgba(8,20,28,0.7)';
        });
        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            zone.style.borderColor = '#1f627a';
            zone.style.background = 'rgba(8,20,28,0.7)';
            const files = e.dataTransfer.files;
            if (files.length > 0) handleFile(files[0], isEncrypt);
        });

        fileInput.addEventListener('change', (e) => {
            if (fileInput.files.length > 0) handleFile(fileInput.files[0], isEncrypt);
        });

        function handleFile(file, isEnc) {
            if (isEnc) {
                encryptFile = file;
                encryptFileName.innerText = `📄 ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
                encryptFileName.style.display = 'inline-block';
                setStatus('📎', `selected: ${file.name}`, true);
            } else {
                decryptFile = file;
                decryptFileName.innerText = `🔐 ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
                decryptFileName.style.display = 'inline-block';
                setStatus('📎', `encrypted file: ${file.name}`, true);
            }
        }
    }

    setupDropZone(encryptDropZone, encryptFileInput, encryptFileName, true);
    setupDropZone(decryptDropZone, decryptFileInput, decryptFileName, false);

    // ---------- status update ----------
    function setStatus(icon, msg, isGood = false) {
        statusIcon.innerText = icon;
        statusMessage.innerText = msg;
        statusMessage.style.color = isGood ? '#b4ffe0' : '#cae9ff';
    }

    // ---------- progress simulation (smooth) ----------
    function startProgress() {
        progressContainer.classList.remove('hidden');
        progressBar.style.width = '0%';
    }
    function advanceProgress(percent) {
        progressBar.style.width = Math.min(percent, 100) + '%';
    }
    function completeProgress() {
        progressBar.style.width = '100%';
        setTimeout(() => {
            progressContainer.classList.add('hidden');
            progressBar.style.width = '0%';
        }, 500);
    }

    // ---------- ENCRYPTION ----------
    encryptBtn.addEventListener('click', async () => {
        if (!encryptFile) {
            setStatus('⚠️', 'no file selected');
            return;
        }
        const password = encryptPassword.value.trim();
        if (!password || password.length < 4) {
            setStatus('❌', 'password too short (min 4 chars)');
            return;
        }

        try {
            setStatus('⏳', 'encrypting...', false);
            startProgress();
            advanceProgress(15);

            const fileBuffer = await encryptFile.arrayBuffer();
            const salt = generateSalt();
            const iv = generateIv();
            const keyMaterial = await getKeyMaterial(password);
            const key = await deriveKey(keyMaterial, salt);

            advanceProgress(50);
            const encryptedContent = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                fileBuffer
            );

            advanceProgress(85);
            // format: salt(16) + iv(12) + encrypted data
            const outputBuffer = new Uint8Array(
                salt.byteLength + iv.byteLength + encryptedContent.byteLength
            );
            outputBuffer.set(new Uint8Array(salt), 0);
            outputBuffer.set(new Uint8Array(iv), salt.byteLength);
            outputBuffer.set(new Uint8Array(encryptedContent), salt.byteLength + iv.byteLength);

            const blob = new Blob([outputBuffer], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = encryptFile.name + '.encrypted';
            a.click();
            URL.revokeObjectURL(url);

            advanceProgress(100);
            setStatus('✅', 'encryption successful · file downloaded', true);
            completeProgress();
        } catch (err) {
            console.error(err);
            setStatus('🔥', 'encryption failed: ' + err.message);
            progressContainer.classList.add('hidden');
        }
    });

    // ---------- DECRYPTION ----------
    decryptBtn.addEventListener('click', async () => {
        if (!decryptFile) {
            setStatus('⚠️', 'no encrypted file selected');
            return;
        }
        const password = decryptPassword.value.trim();
        if (!password) {
            setStatus('❌', 'enter password');
            return;
        }

        try {
            setStatus('⏳', 'decrypting...', false);
            startProgress();
            advanceProgress(20);

            const fileBuffer = await decryptFile.arrayBuffer();
            const fileBytes = new Uint8Array(fileBuffer);

            if (fileBytes.length < 28) { // 16 salt + 12 iv
                throw new Error('invalid encrypted file (too small)');
            }

            const salt = fileBytes.slice(0, 16);
            const iv = fileBytes.slice(16, 28);
            const encryptedData = fileBytes.slice(28);

            const keyMaterial = await getKeyMaterial(password);
            const key = await deriveKey(keyMaterial, salt);

            advanceProgress(60);
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                encryptedData
            );

            advanceProgress(90);
            // reconstruct original filename
            let originalName = decryptFile.name;
            if (originalName.endsWith('.encrypted')) {
                originalName = originalName.slice(0, -10); // remove .encrypted
            } else {
                originalName = 'decrypted_' + originalName;
            }

            const blob = new Blob([decryptedBuffer]);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = originalName;
            a.click();
            URL.revokeObjectURL(url);

            advanceProgress(100);
            setStatus('✅', 'decryption successful · file restored', true);
            completeProgress();
        } catch (err) {
            console.error(err);
            setStatus('🔥', 'decryption failed · wrong password or corrupted file');
            progressContainer.classList.add('hidden');
        }
    });

    // ---------- set default mode ----------
    setMode('encrypt');
    // cleanup on page unload? nothing persistent
})();