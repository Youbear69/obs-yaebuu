/* ═══════════════════════════════════════════════════════════
   OBS Web Controller — Application Logic
   Native OBS WebSocket v5 protocol implementation
   No external dependencies required
   ═══════════════════════════════════════════════════════════ */

// ─── OBS WebSocket Protocol Client ───
class OBSWebSocketClient {
    constructor() {
        this.ws = null;
        this.requestCounter = 0;
        this.pendingRequests = new Map();
        this.eventListeners = new Map();
        this.connected = false;
        this.identified = false;
    }

    async connect(host, port, password) {
        return new Promise((resolve, reject) => {
            const url = `ws://${host}:${port}`;

            try {
                this.ws = new WebSocket(url);
            } catch (e) {
                reject(new Error('Failed to create WebSocket connection'));
                return;
            }

            let authTimeout = setTimeout(() => {
                reject(new Error('Connection timeout — no response from OBS'));
                this.disconnect();
            }, 8000);

            this.ws.onopen = () => {
                // Wait for Hello message from server
            };

            this.ws.onmessage = async (event) => {
                let msg;
                try {
                    msg = JSON.parse(event.data);
                } catch {
                    return;
                }

                switch (msg.op) {
                    case 0: // Hello
                        try {
                            await this._identify(msg.d, password);
                        } catch (e) {
                            clearTimeout(authTimeout);
                            reject(e);
                        }
                        break;

                    case 2: // Identified
                        clearTimeout(authTimeout);
                        this.connected = true;
                        this.identified = true;
                        resolve(msg.d);
                        break;

                    case 5: // Event
                        this._dispatchEvent(msg.d.eventType, msg.d.eventData || {});
                        break;

                    case 7: // RequestResponse
                        this._handleResponse(msg.d);
                        break;

                    case 9: // RequestBatchResponse
                        break;
                }
            };

            this.ws.onerror = () => {
                clearTimeout(authTimeout);
                reject(new Error('WebSocket connection error — check server address and port'));
            };

            this.ws.onclose = (event) => {
                clearTimeout(authTimeout);
                this.connected = false;
                this.identified = false;

                // OBS WebSocket close codes
                const closeMessages = {
                    4009: 'Authentication failed — incorrect password',
                    4010: 'Authentication required but no password provided',
                    4008: 'Authentication timeout',
                    4005: 'Invalid message format',
                    4003: 'Missing data',
                    4011: 'Incompatible RPC version',
                };

                if (closeMessages[event.code]) {
                    reject(new Error(closeMessages[event.code]));
                } else if (!this.identified) {
                    reject(new Error(`Connection closed (code: ${event.code})`));
                }

                this._dispatchEvent('ConnectionClosed', { code: event.code });
            };
        });
    }

    async _identify(hello, password) {
        const identifyData = {
            rpcVersion: 1,
            // Subscribe to: General, Config, Scenes, Inputs, Transitions, Filters, Outputs, SceneItems
            eventSubscriptions: 2047 // All standard event categories
        };

        if (hello.authentication) {
            if (!password) {
                throw new Error('Server requires a password');
            }
            identifyData.authentication = await this._generateAuth(
                password,
                hello.authentication.salt,
                hello.authentication.challenge
            );
        }

        this.ws.send(JSON.stringify({ op: 1, d: identifyData }));
    }

    async _generateAuth(password, salt, challenge) {
        // Use native Web Crypto API if available (HTTPS or localhost)
        if (window.crypto && window.crypto.subtle) {
            const encoder = new TextEncoder();
            const secretBuf = await window.crypto.subtle.digest('SHA-256', encoder.encode(password + salt));
            const base64Secret = btoa(String.fromCharCode(...new Uint8Array(secretBuf)));
            const authBuf = await window.crypto.subtle.digest('SHA-256', encoder.encode(base64Secret + challenge));
            return btoa(String.fromCharCode(...new Uint8Array(authBuf)));
        } 
        // Fallback for non-secure contexts (LAN access via HTTP)
        else {
            const base64Secret = this._hexToBase64(this._sha256(password + salt));
            return this._hexToBase64(this._sha256(base64Secret + challenge));
        }
    }

    _hexToBase64(hex) {
        return btoa(hex.match(/\w{2}/g).map(a => String.fromCharCode(parseInt(a, 16))).join(""));
    }

    // Compact Pure JS SHA-256 Implementation
    _sha256(ascii) {
        function rightRotate(value, amount) { return (value>>>amount) | (value<<(32 - amount)); }
        var mathPow = Math.pow, maxWord = mathPow(2, 32), lengthProperty = 'length', i, j, result = '', words = [], asciiBitLength = ascii[lengthProperty]*8;
        var hash = this._sha256.h = this._sha256.h || [], k = this._sha256.k = this._sha256.k || [], primeCounter = k[lengthProperty];
        var isComposite = {};
        for (var candidate = 2; primeCounter < 64; candidate++) {
            if (!isComposite[candidate]) {
                for (i = 0; i < 313; i += candidate) isComposite[i] = candidate;
                hash[primeCounter] = (mathPow(candidate, .5)*maxWord)|0;
                k[primeCounter++] = (mathPow(candidate, 1/3)*maxWord)|0;
            }
        }
        ascii += '\x80';
        while (ascii[lengthProperty]%64 - 56) ascii += '\x00';
        for (i = 0; i < ascii[lengthProperty]; i++) {
            j = ascii.charCodeAt(i);
            if (j>>8) return; 
            words[i>>2] |= j << ((3 - i)%4)*8;
        }
        words[words[lengthProperty]] = ((asciiBitLength/maxWord)|0);
        words[words[lengthProperty]] = (asciiBitLength);
        for (j = 0; j < words[lengthProperty];) {
            var w = words.slice(j, j += 16), oldHash = hash;
            hash = hash.slice(0, 8);
            for (i = 0; i < 64; i++) {
                var w15 = w[i - 15], w2 = w[i - 2], a = hash[0], e = hash[4];
                var temp1 = hash[7] + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) + ((e&hash[5])^((~e)&hash[6])) + k[i] + (w[i] = (i < 16) ? w[i] : (w[i - 16] + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15>>>3)) + w[i - 7] + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2>>>10)))|0);
                var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) + ((a&hash[1])^(a&hash[2])^(hash[1]&hash[2]));
                hash = [(temp1 + temp2)|0].concat(hash);
                hash[4] = (hash[4] + temp1)|0;
            }
            for (i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i])|0;
        }
        for (i = 0; i < 8; i++) {
            for (j = 3; j + 1; j--) {
                var b = (hash[i]>>(j*8))&255;
                result += ((b < 16) ? 0 : '') + b.toString(16);
            }
        }
        return result;
    }

    async call(requestType, requestData = {}) {
        if (!this.connected || !this.ws) {
            throw new Error('Not connected to OBS');
        }

        const requestId = `r${++this.requestCounter}_${Date.now()}`;

        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                this.pendingRequests.delete(requestId);
                reject(new Error(`Request "${requestType}" timed out`));
            }, 15000);

            this.pendingRequests.set(requestId, {
                resolve: (data) => { clearTimeout(timeout); resolve(data); },
                reject: (err) => { clearTimeout(timeout); reject(err); },
                type: requestType
            });

            this.ws.send(JSON.stringify({
                op: 6,
                d: {
                    requestType,
                    requestId,
                    requestData: Object.keys(requestData).length > 0 ? requestData : undefined
                }
            }));
        });
    }

    _handleResponse(data) {
        const pending = this.pendingRequests.get(data.requestId);
        if (!pending) return;

        this.pendingRequests.delete(data.requestId);

        if (data.requestStatus.result) {
            pending.resolve(data.responseData || {});
        } else {
            const comment = data.requestStatus.comment || `Request failed with code ${data.requestStatus.code}`;
            pending.reject(new Error(`${pending.type}: ${comment}`));
        }
    }

    on(eventType, handler) {
        if (!this.eventListeners.has(eventType)) {
            this.eventListeners.set(eventType, new Set());
        }
        this.eventListeners.get(eventType).add(handler);
    }

    off(eventType, handler) {
        const listeners = this.eventListeners.get(eventType);
        if (listeners) listeners.delete(handler);
    }

    _dispatchEvent(eventType, eventData) {
        const listeners = this.eventListeners.get(eventType);
        if (listeners) {
            listeners.forEach(handler => {
                try { handler(eventData); } catch (e) { console.error(`Event handler error (${eventType}):`, e); }
            });
        }
        // Also dispatch to wildcard listeners
        const wildcard = this.eventListeners.get('*');
        if (wildcard) {
            wildcard.forEach(handler => {
                try { handler(eventType, eventData); } catch (e) { console.error('Wildcard handler error:', e); }
            });
        }
    }

    disconnect() {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
        this.connected = false;
        this.identified = false;
        this.pendingRequests.clear();
    }
}


// ─── Main Application Controller ───
class OBSController {
    constructor() {
        this.obs = new OBSWebSocketClient();
        this.state = {
            connected: false,
            scenes: [],
            currentScene: '',
            currentPreviewScene: '',
            sources: [],
            audioInputs: [],
            transitions: [],
            currentTransition: '',
            transitionDuration: 300,
            isStreaming: false,
            isRecording: false,
            isVirtualCam: false,
            studioMode: false,
            streamTimecode: '00:00:00',
            recordTimecode: '00:00:00',
            inputKinds: [],
            previewRunning: false,
        };

        this.previewInterval = null;
        this.statsInterval = null;
        this.host = '';
        this.port = '';

        this._cacheDom();
        this._bindEvents();
        this._initParticles();
    }

    // ─── DOM Cache ───
    _cacheDom() {
        // Connection
        this.dom = {
            overlay: document.getElementById('connectionOverlay'),
            mainUI: document.getElementById('mainUI'),
            serverHost: document.getElementById('serverHost'),
            serverPort: document.getElementById('serverPort'),
            serverPassword: document.getElementById('serverPassword'),
            connectBtn: document.getElementById('connectBtn'),
            connectBtnText: document.querySelector('.btn-connect-text'),
            connectBtnLoader: document.querySelector('.btn-connect-loader'),
            connectError: document.getElementById('connectError'),
            togglePasswordBtn: document.getElementById('togglePasswordBtn'),

            // Top bar
            connectionLabel: document.getElementById('connectionLabel'),
            connectionBadge: document.getElementById('connectionBadge'),
            btnStudioMode: document.getElementById('btnStudioMode'),
            btnDisconnect: document.getElementById('btnDisconnect'),

            // Preview
            previewSection: document.getElementById('previewSection'),
            previewBox: document.getElementById('previewBox'),
            previewImg: document.getElementById('previewImg'),
            previewFallback: document.getElementById('previewFallback'),
            previewLabel: document.getElementById('previewLabel'),
            programBox: document.getElementById('programBox'),
            programImg: document.getElementById('programImg'),
            programFallback: document.getElementById('programFallback'),
            studioTransitionBar: document.getElementById('studioTransitionBar'),
            studioTransSelect: document.getElementById('studioTransSelect'),
            studioTransDuration: document.getElementById('studioTransDuration'),
            studioTransBtn: document.getElementById('studioTransBtn'),

            // Scenes
            sceneList: document.getElementById('sceneList'),

            // Sources
            sourceList: document.getElementById('sourceList'),

            // Audio Mixer
            mixerBody: document.getElementById('mixerBody'),

            // Controls
            btnStartStream: document.getElementById('btnStartStream'),
            btnStartRecord: document.getElementById('btnStartRecord'),
            btnStartVCam: document.getElementById('btnStartVCam'),
            btnStudioMode2: document.getElementById('btnStudioMode2'),

            // Transitions
            transitionPicker: document.getElementById('transitionPicker'),
            transitionDurInput: document.getElementById('transitionDurInput'),

            // Status bar
            streamStatusBadge: document.getElementById('streamStatusBadge'),
            recordStatusBadge: document.getElementById('recordStatusBadge'),
            streamTimer: document.getElementById('streamTimer'),
            recordTimer: document.getElementById('recordTimer'),
            obsStats: document.getElementById('obsStats'),

            // Modals
            modalAddScene: document.getElementById('modalAddScene'),
            modalAddSource: document.getElementById('modalAddSource'),
            newSceneName: document.getElementById('newSceneName'),
            newSourceType: document.getElementById('newSourceType'),
            newSourceName: document.getElementById('newSourceName'),
            btnAddScene: document.getElementById('btnAddScene'),
            btnAddSource: document.getElementById('btnAddSource'),
            btnConfirmAddScene: document.getElementById('btnConfirmAddScene'),
            btnConfirmAddSource: document.getElementById('btnConfirmAddSource'),
        };
    }

    // ─── Event Bindings ───
    _bindEvents() {
        // Connection
        this.dom.connectBtn.addEventListener('click', () => this.connect());
        this.dom.serverPassword.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') this.connect();
        });
        this.dom.serverHost.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') this.connect();
        });
        this.dom.togglePasswordBtn.addEventListener('click', () => {
            const input = this.dom.serverPassword;
            input.type = input.type === 'password' ? 'text' : 'password';
            this.dom.togglePasswordBtn.textContent = input.type === 'password' ? '👁' : '🙈';
        });

        // Top bar
        this.dom.btnDisconnect.addEventListener('click', () => this.disconnect());
        this.dom.btnStudioMode.addEventListener('click', () => this.toggleStudioMode());

        // Controls
        this.dom.btnStartStream.addEventListener('click', () => this.toggleStream());
        this.dom.btnStartRecord.addEventListener('click', () => this.toggleRecord());
        this.dom.btnStartVCam.addEventListener('click', () => this.toggleVirtualCam());
        this.dom.btnStudioMode2.addEventListener('click', () => this.toggleStudioMode());

        // Studio transition
        this.dom.studioTransBtn.addEventListener('click', () => this.triggerStudioTransition());
        this.dom.studioTransSelect.addEventListener('change', (e) => {
            this.setTransition(e.target.value);
        });
        this.dom.studioTransDuration.addEventListener('change', (e) => {
            this.setTransitionDuration(parseInt(e.target.value) || 300);
        });

        // Transition picker (in tab)
        this.dom.transitionPicker.addEventListener('change', (e) => {
            this.setTransition(e.target.value);
        });
        this.dom.transitionDurInput.addEventListener('change', (e) => {
            this.setTransitionDuration(parseInt(e.target.value) || 300);
        });

        // Modals
        this.dom.btnAddScene.addEventListener('click', () => this.showModal('modalAddScene'));
        this.dom.btnAddSource.addEventListener('click', () => this.showModal('modalAddSource'));
        document.querySelectorAll('[data-close]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const modalId = e.currentTarget.dataset.close;
                this.hideModal(modalId);
            });
        });
        this.dom.btnConfirmAddScene.addEventListener('click', () => this.createScene());
        this.dom.btnConfirmAddSource.addEventListener('click', () => this.createSource());

        // Tabs
        document.querySelectorAll('.dock-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                const tabId = tab.dataset.tab;
                const parent = tab.closest('.dock-panel');
                parent.querySelectorAll('.dock-tab').forEach(t => t.classList.remove('active'));
                parent.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById(tabId)?.classList.add('active');
            });
        });

        // OBS Events
        this.obs.on('CurrentProgramSceneChanged', (d) => {
            this.state.currentScene = d.sceneName;
            this._renderScenes();
            this._loadSources();
        });
        this.obs.on('CurrentPreviewSceneChanged', (d) => {
            this.state.currentPreviewScene = d.sceneName;
            this._renderScenes();
        });
        this.obs.on('SceneListChanged', (d) => {
            this.state.scenes = d.scenes.map(s => s.sceneName).reverse();
            this._renderScenes();
        });
        this.obs.on('StreamStateChanged', (d) => {
            this.state.isStreaming = d.outputActive;
            this._updateStreamUI();
        });
        this.obs.on('RecordStateChanged', (d) => {
            this.state.isRecording = d.outputActive;
            this._updateRecordUI();
        });
        this.obs.on('VirtualcamStateChanged', (d) => {
            this.state.isVirtualCam = d.outputActive;
            this._updateVCamUI();
        });
        this.obs.on('StudioModeStateChanged', (d) => {
            this.state.studioMode = d.studioModeEnabled;
            this._updateStudioModeUI();
        });
        this.obs.on('SceneItemEnableStateChanged', (d) => {
            if (d.sceneName === this.state.currentScene) {
                this._loadSources();
            }
        });
        this.obs.on('InputVolumeChanged', (d) => {
            this._updateMixerChannel(d.inputName, { volumeDb: d.inputVolumeDb });
        });
        this.obs.on('InputMuteStateChanged', (d) => {
            this._updateMixerChannel(d.inputName, { muted: d.inputMuted });
        });
        this.obs.on('CurrentSceneTransitionChanged', (d) => {
            this.state.currentTransition = d.transitionName;
            this._syncTransitionSelects();
        });
        this.obs.on('CurrentSceneTransitionDurationChanged', (d) => {
            this.state.transitionDuration = d.transitionDuration;
            this._syncTransitionDuration();
        });
        this.obs.on('SceneItemListReindexed', () => {
            this._loadSources();
        });
        this.obs.on('InputNameChanged', (d) => {
            this._loadAudioInputs();
        });
        this.obs.on('ConnectionClosed', () => {
            if (this.state.connected) {
                this.state.connected = false;
                this._showOverlay();
                this._stopPolling();
                this._showConnectError('Connection lost — OBS may have closed');
            }
        });
    }

    // ─── Connection Flow ───
    async connect() {
        const host = this.dom.serverHost.value.trim() || 'localhost';
        const port = this.dom.serverPort.value.trim() || '4455';
        const password = this.dom.serverPassword.value;

        this._hideConnectError();
        this._setConnecting(true);

        try {
            await this.obs.connect(host, port, password);
            this.host = host;
            this.port = port;
            this.state.connected = true;
            this.dom.connectionLabel.textContent = `Connected to ${host}:${port}`;

            // Load initial state
            await this._loadInitialState();

            // Show main UI
            this._showMainUI();

            // Start polling
            this._startPolling();
        } catch (err) {
            this._showConnectError(err.message);
        } finally {
            this._setConnecting(false);
        }
    }

    disconnect() {
        this.obs.disconnect();
        this.state.connected = false;
        this._stopPolling();
        this._showOverlay();
    }

    // ─── Initial State Loading ───
    async _loadInitialState() {
        try {
            // Load scenes
            const sceneData = await this.obs.call('GetSceneList');
            this.state.scenes = (sceneData.scenes || []).map(s => s.sceneName).reverse();
            this.state.currentScene = sceneData.currentProgramSceneName || '';
            this.state.currentPreviewScene = sceneData.currentPreviewSceneName || '';
            this._renderScenes();

            // Load sources for current scene
            await this._loadSources();

            // Load audio inputs
            await this._loadAudioInputs();

            // Load transitions
            await this._loadTransitions();

            // Load stream/record/vcam status
            await this._loadOutputStatus();

            // Load studio mode
            await this._loadStudioMode();

            // Load input kinds for Add Source modal
            await this._loadInputKinds();

        } catch (err) {
            console.error('Error loading initial state:', err);
        }
    }

    // ─── Scenes ───
    async switchScene(sceneName) {
        try {
            if (this.state.studioMode) {
                await this.obs.call('SetCurrentPreviewScene', { sceneName });
                this.state.currentPreviewScene = sceneName;
            } else {
                await this.obs.call('SetCurrentProgramScene', { sceneName });
                this.state.currentScene = sceneName;
            }
            this._renderScenes();
            await this._loadSources();
        } catch (err) {
            console.error('Error switching scene:', err);
        }
    }

    _renderScenes() {
        const container = this.dom.sceneList;
        container.innerHTML = '';

        this.state.scenes.forEach(name => {
            const item = document.createElement('div');
            item.className = 'scene-item';

            const isProgram = name === this.state.currentScene;
            const isPreview = this.state.studioMode && name === this.state.currentPreviewScene;

            if (isProgram && !this.state.studioMode) item.classList.add('active');
            if (isPreview && this.state.studioMode) item.classList.add('active');
            if (isProgram && this.state.studioMode) {
                item.style.borderLeftColor = '#ff4757';
                item.style.background = 'rgba(255,71,87,0.1)';
            }

            item.innerHTML = `<span class="scene-item-name">${this._escapeHtml(name)}</span>`;
            item.addEventListener('click', () => this.switchScene(name));
            container.appendChild(item);
        });
    }

    // ─── Sources ───
    async _loadSources() {
        if (!this.state.currentScene) return;

        try {
            const data = await this.obs.call('GetSceneItemList', { sceneName: this.state.currentScene });
            this.state.sources = (data.sceneItems || []).reverse();
            this._renderSources();
        } catch (err) {
            console.error('Error loading sources:', err);
        }
    }

    _renderSources() {
        const container = this.dom.sourceList;
        container.innerHTML = '';

        this.state.sources.forEach(src => {
            const item = document.createElement('div');
            item.className = 'source-item';

            const icon = this._getSourceIcon(src.inputKind || src.sourceType || '');
            const visible = src.sceneItemEnabled;

            item.innerHTML = `
                <span class="source-icon">${icon}</span>
                <span class="source-name" title="${this._escapeHtml(src.sourceName)}">${this._escapeHtml(src.sourceName)}</span>
                <div class="source-actions">
                    <button class="source-toggle ${visible ? 'visible-on' : 'visible-off'}"
                            title="${visible ? 'Hide' : 'Show'}"
                            data-id="${src.sceneItemId}"
                            data-visible="${visible}">
                        ${visible ? '👁' : '👁‍🗨'}
                    </button>
                </div>
            `;

            const toggleBtn = item.querySelector('.source-toggle');
            toggleBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.toggleSourceVisibility(src.sceneItemId, !visible);
            });

            container.appendChild(item);
        });
    }

    async toggleSourceVisibility(sceneItemId, enabled) {
        try {
            await this.obs.call('SetSceneItemEnabled', {
                sceneName: this.state.currentScene,
                sceneItemId,
                sceneItemEnabled: enabled
            });
            await this._loadSources();
        } catch (err) {
            console.error('Error toggling source visibility:', err);
        }
    }

    _getSourceIcon(kind) {
        const iconMap = {
            'browser_source': '🌐',
            'image_source': '🖼️',
            'ffmpeg_source': '🎬',
            'vlc_source': '🎬',
            'text_gdiplus_v2': '📝',
            'text_gdiplus_v3': '📝',
            'text_gdiplus': '📝',
            'text_ft2_source': '📝',
            'text_ft2_source_v2': '📝',
            'game_capture': '🎮',
            'window_capture': '🪟',
            'monitor_capture': '🖥️',
            'display_capture': '🖥️',
            'audio_input_capture': '🎤',
            'audio_output_capture': '🔊',
            'wasapi_input_capture': '🎤',
            'wasapi_output_capture': '🔊',
            'pulse_input_capture': '🎤',
            'pulse_output_capture': '🔊',
            'dshow_input': '📷',
            'scene': '📁',
            'group': '📂',
            'color_source_v3': '🎨',
            'color_source': '🎨',
            'slideshow': '🖼️',
            'ndi_source': '📡',
        };
        return iconMap[kind] || '📦';
    }

    // ─── Audio Mixer ───
    async _loadAudioInputs() {
        try {
            // Get all inputs
            const inputData = await this.obs.call('GetInputList');
            const inputs = inputData.inputs || [];

            // Also get special inputs (global audio devices)
            let specialInputs = {};
            try {
                specialInputs = await this.obs.call('GetSpecialInputs');
            } catch {
                // Might not be available
            }

            const specialNames = new Set(Object.values(specialInputs).filter(Boolean));

            // For each input, try to get volume info
            const audioInputs = [];

            for (const input of inputs) {
                try {
                    const volumeData = await this.obs.call('GetInputVolume', { inputName: input.inputName });
                    const muteData = await this.obs.call('GetInputMute', { inputName: input.inputName });

                    audioInputs.push({
                        name: input.inputName,
                        kind: input.inputKind,
                        volumeDb: volumeData.inputVolumeDb,
                        volumeMul: volumeData.inputVolumeMul,
                        muted: muteData.inputMuted,
                        isGlobal: specialNames.has(input.inputName)
                    });
                } catch {
                    // Input doesn't support audio — skip
                }
            }

            this.state.audioInputs = audioInputs;
            this._renderMixer();
        } catch (err) {
            console.error('Error loading audio inputs:', err);
        }
    }

    _renderMixer() {
        const container = this.dom.mixerBody;

        if (this.state.audioInputs.length === 0) {
            container.innerHTML = '<div class="mixer-empty">No audio sources</div>';
            return;
        }

        container.innerHTML = '';

        this.state.audioInputs.forEach(input => {
            const channel = document.createElement('div');
            channel.className = 'mixer-channel';
            channel.dataset.inputName = input.name;

            const dbDisplay = input.volumeDb !== null && input.volumeDb !== undefined
                ? `${input.volumeDb.toFixed(1)} dB`
                : '-- dB';

            // Convert dB to slider value (range: -100 to 0)
            const sliderValue = Math.max(-100, Math.min(0, input.volumeDb || 0));

            // Simple truncated name
            const shortName = input.name.length > 12
                ? input.name.substring(0, 11) + '…'
                : input.name;

            channel.innerHTML = `
                <div class="mixer-type ${input.isGlobal ? 'global' : 'active'}">${input.isGlobal ? 'Global' : 'Active'}</div>
                <div class="mixer-label" title="${this._escapeHtml(input.name)}">${this._escapeHtml(shortName)}</div>
                <div class="mixer-db" data-db-display>${dbDisplay}</div>
                <div class="fader-area">
                    <div class="meter-wrap">
                        <div class="meter-bar"><div class="meter-fill" data-meter-l style="height: 0%"></div></div>
                        <div class="meter-bar"><div class="meter-fill" data-meter-r style="height: 0%"></div></div>
                    </div>
                    <input type="range" class="volume-fader" min="-100" max="0" step="0.5" value="${sliderValue}"
                           data-input-name="${this._escapeHtml(input.name)}">
                    <div class="db-scale">
                        <span>0</span>
                        <span>-6</span>
                        <span>-12</span>
                        <span>-18</span>
                        <span>-24</span>
                        <span>-30</span>
                        <span>-48</span>
                        <span>-60</span>
                    </div>
                </div>
                <div class="mixer-controls">
                    <button class="mute-btn ${input.muted ? 'muted' : ''}"
                            data-input-name="${this._escapeHtml(input.name)}"
                            title="${input.muted ? 'Unmute' : 'Mute'}">
                        ${input.muted ? '🔇' : '🔊'}
                    </button>
                </div>
            `;

            // Volume fader event
            const fader = channel.querySelector('.volume-fader');
            let faderDebounce = null;
            fader.addEventListener('input', () => {
                const db = parseFloat(fader.value);
                const dbLabel = channel.querySelector('[data-db-display]');
                dbLabel.textContent = `${db.toFixed(1)} dB`;

                // Simulate meter based on fader position
                const meterPct = Math.max(0, ((db + 100) / 100) * 80);
                channel.querySelector('[data-meter-l]').style.height = `${meterPct}%`;
                channel.querySelector('[data-meter-r]').style.height = `${meterPct * 0.9}%`;

                clearTimeout(faderDebounce);
                faderDebounce = setTimeout(() => {
                    this.setVolume(input.name, db);
                }, 50);
            });

            // Mute button event
            const muteBtn = channel.querySelector('.mute-btn');
            muteBtn.addEventListener('click', () => {
                this.toggleMute(input.name);
            });

            container.appendChild(channel);

            // Initialize meter based on current volume
            const initialPct = Math.max(0, ((sliderValue + 100) / 100) * 80);
            const meterL = channel.querySelector('[data-meter-l]');
            const meterR = channel.querySelector('[data-meter-r]');
            if (!input.muted) {
                setTimeout(() => {
                    meterL.style.height = `${initialPct}%`;
                    meterR.style.height = `${initialPct * 0.9}%`;
                }, 100);
            }
        });
    }

    async setVolume(inputName, volumeDb) {
        try {
            await this.obs.call('SetInputVolume', {
                inputName,
                inputVolumeDb: volumeDb
            });
        } catch (err) {
            console.error('Error setting volume:', err);
        }
    }

    async toggleMute(inputName) {
        try {
            const result = await this.obs.call('ToggleInputMute', { inputName });
            this._updateMixerChannel(inputName, { muted: result.inputMuted });
        } catch (err) {
            console.error('Error toggling mute:', err);
        }
    }

    _updateMixerChannel(inputName, updates) {
        const channel = this.dom.mixerBody.querySelector(`[data-input-name="${CSS.escape(inputName)}"]`)?.closest('.mixer-channel');
        if (!channel) return;

        if (updates.volumeDb !== undefined) {
            const dbLabel = channel.querySelector('[data-db-display]');
            if (dbLabel) dbLabel.textContent = `${updates.volumeDb.toFixed(1)} dB`;

            const fader = channel.querySelector('.volume-fader');
            if (fader) fader.value = Math.max(-100, Math.min(0, updates.volumeDb));

            const pct = Math.max(0, ((updates.volumeDb + 100) / 100) * 80);
            const meterL = channel.querySelector('[data-meter-l]');
            const meterR = channel.querySelector('[data-meter-r]');
            if (meterL) meterL.style.height = `${pct}%`;
            if (meterR) meterR.style.height = `${pct * 0.9}%`;
        }

        if (updates.muted !== undefined) {
            const muteBtn = channel.querySelector('.mute-btn');
            if (muteBtn) {
                muteBtn.classList.toggle('muted', updates.muted);
                muteBtn.textContent = updates.muted ? '🔇' : '🔊';
                muteBtn.title = updates.muted ? 'Unmute' : 'Mute';
            }

            if (updates.muted) {
                const meterL = channel.querySelector('[data-meter-l]');
                const meterR = channel.querySelector('[data-meter-r]');
                if (meterL) meterL.style.height = '0%';
                if (meterR) meterR.style.height = '0%';
            }
        }
    }

    // ─── Stream / Record / Virtual Camera ───
    async _loadOutputStatus() {
        try {
            const streamStatus = await this.obs.call('GetStreamStatus');
            this.state.isStreaming = streamStatus.outputActive;
            this.state.streamTimecode = streamStatus.outputTimecode || '00:00:00';
            this._updateStreamUI();
        } catch {}

        try {
            const recordStatus = await this.obs.call('GetRecordStatus');
            this.state.isRecording = recordStatus.outputActive;
            this.state.recordTimecode = recordStatus.outputTimecode || '00:00:00';
            this._updateRecordUI();
        } catch {}

        try {
            const vcamStatus = await this.obs.call('GetVirtualCamStatus');
            this.state.isVirtualCam = vcamStatus.outputActive;
            this._updateVCamUI();
        } catch {}
    }

    async toggleStream() {
        try {
            const result = await this.obs.call('ToggleStream');
            this.state.isStreaming = result.outputActive;
            this._updateStreamUI();
        } catch (err) {
            console.error('Error toggling stream:', err);
        }
    }

    async toggleRecord() {
        try {
            const result = await this.obs.call('ToggleRecord');
            this.state.isRecording = result.outputActive;
            this._updateRecordUI();
        } catch (err) {
            console.error('Error toggling record:', err);
        }
    }

    async toggleVirtualCam() {
        try {
            const result = await this.obs.call('ToggleVirtualCam');
            this.state.isVirtualCam = result.outputActive;
            this._updateVCamUI();
        } catch (err) {
            console.error('Error toggling virtual camera:', err);
        }
    }

    _updateStreamUI() {
        const btn = this.dom.btnStartStream;
        const badge = this.dom.streamStatusBadge;
        const timer = this.dom.streamTimer;

        if (this.state.isStreaming) {
            btn.innerHTML = '<span class="ctrl-icon">📡</span> Stop Streaming';
            btn.classList.add('streaming');
            badge.className = 'sb-badge live';
            badge.innerHTML = '<span class="sb-dot"></span> LIVE: ON';
            timer.classList.remove('hidden');
        } else {
            btn.innerHTML = '<span class="ctrl-icon">📡</span> Start Streaming';
            btn.classList.remove('streaming');
            badge.className = 'sb-badge';
            badge.innerHTML = '<span class="sb-dot"></span> LIVE: OFF';
            timer.classList.add('hidden');
        }
    }

    _updateRecordUI() {
        const btn = this.dom.btnStartRecord;
        const badge = this.dom.recordStatusBadge;
        const timer = this.dom.recordTimer;

        if (this.state.isRecording) {
            btn.innerHTML = '<span class="ctrl-icon">⏹</span> Stop Recording';
            btn.classList.add('recording');
            badge.className = 'sb-badge rec';
            badge.innerHTML = '<span class="sb-dot"></span> REC: ON';
            timer.classList.remove('hidden');
        } else {
            btn.innerHTML = '<span class="ctrl-icon">⏺</span> Start Recording';
            btn.classList.remove('recording');
            badge.className = 'sb-badge';
            badge.innerHTML = '<span class="sb-dot"></span> REC: OFF';
            timer.classList.add('hidden');
        }
    }

    _updateVCamUI() {
        const btn = this.dom.btnStartVCam;
        if (this.state.isVirtualCam) {
            btn.innerHTML = '<span class="ctrl-icon">📷</span> Stop Virtual Camera';
            btn.classList.add('vcam-active');
        } else {
            btn.innerHTML = '<span class="ctrl-icon">📷</span> Start Virtual Camera';
            btn.classList.remove('vcam-active');
        }
    }

    // ─── Studio Mode ───
    async _loadStudioMode() {
        try {
            const result = await this.obs.call('GetStudioModeEnabled');
            this.state.studioMode = result.studioModeEnabled;
            this._updateStudioModeUI();
        } catch {
            this.state.studioMode = false;
        }
    }

    async toggleStudioMode() {
        try {
            this.state.studioMode = !this.state.studioMode;
            await this.obs.call('SetStudioModeEnabled', {
                studioModeEnabled: this.state.studioMode
            });
            this._updateStudioModeUI();

            if (this.state.studioMode) {
                // Reload preview scene
                try {
                    const sceneData = await this.obs.call('GetSceneList');
                    this.state.currentPreviewScene = sceneData.currentPreviewSceneName || '';
                    this._renderScenes();
                } catch {}
            }
        } catch (err) {
            console.error('Error toggling studio mode:', err);
            this.state.studioMode = !this.state.studioMode;
        }
    }

    _updateStudioModeUI() {
        const isStudio = this.state.studioMode;

        // Top bar button
        this.dom.btnStudioMode.classList.toggle('studio-active', isStudio);

        // Control panel button
        this.dom.btnStudioMode2.classList.toggle('studio-active', isStudio);
        this.dom.btnStudioMode2.innerHTML = `<span class="ctrl-icon">⊞</span> Studio Mode ${isStudio ? '(ON)' : ''}`;

        // Program preview box
        this.dom.programBox.classList.toggle('hidden', !isStudio);

        // Transition bar
        this.dom.studioTransitionBar.classList.toggle('hidden', !isStudio);

        // Preview label
        if (isStudio) {
            this.dom.previewLabel.textContent = 'Preview';
        } else {
            this.dom.previewLabel.textContent = 'Preview';
        }

        this._renderScenes();
    }

    async triggerStudioTransition() {
        try {
            await this.obs.call('TriggerStudioModeTransition');
        } catch (err) {
            console.error('Error triggering transition:', err);
        }
    }

    // ─── Transitions ───
    async _loadTransitions() {
        try {
            const data = await this.obs.call('GetSceneTransitionList');
            this.state.transitions = (data.transitions || []).map(t => t.transitionName);
            this.state.currentTransition = data.currentSceneTransitionName || '';

            // Get current transition duration
            try {
                const current = await this.obs.call('GetCurrentSceneTransition');
                this.state.transitionDuration = current.transitionDuration || 300;
            } catch {}

            this._renderTransitionSelects();
        } catch (err) {
            console.error('Error loading transitions:', err);
        }
    }

    _renderTransitionSelects() {
        const selects = [this.dom.transitionPicker, this.dom.studioTransSelect];

        selects.forEach(select => {
            select.innerHTML = '';
            this.state.transitions.forEach(name => {
                const opt = document.createElement('option');
                opt.value = name;
                opt.textContent = name;
                opt.selected = name === this.state.currentTransition;
                select.appendChild(opt);
            });
        });

        this._syncTransitionDuration();
    }

    _syncTransitionSelects() {
        [this.dom.transitionPicker, this.dom.studioTransSelect].forEach(select => {
            select.value = this.state.currentTransition;
        });
    }

    _syncTransitionDuration() {
        this.dom.transitionDurInput.value = this.state.transitionDuration;
        this.dom.studioTransDuration.value = this.state.transitionDuration;
    }

    async setTransition(name) {
        try {
            await this.obs.call('SetCurrentSceneTransition', { transitionName: name });
            this.state.currentTransition = name;
            this._syncTransitionSelects();
        } catch (err) {
            console.error('Error setting transition:', err);
        }
    }

    async setTransitionDuration(duration) {
        try {
            await this.obs.call('SetCurrentSceneTransitionDuration', { transitionDuration: duration });
            this.state.transitionDuration = duration;
            this._syncTransitionDuration();
        } catch (err) {
            console.error('Error setting transition duration:', err);
        }
    }

    // ─── Preview Screenshots (High FPS) ───
    async _runPreviewLoop() {
        if (!this.state.connected || !this.state.previewRunning) return;

        try {
            const sceneName = this.state.studioMode
                ? (this.state.currentPreviewScene || this.state.currentScene)
                : this.state.currentScene;

            if (sceneName) {
                const result = await this.obs.call('GetSourceScreenshot', {
                    sourceName: sceneName,
                    imageFormat: 'jpeg',
                    imageWidth: 640,
                    imageHeight: 360,
                    imageCompressionQuality: 10
                });

                if (result.imageData) {
                    this.dom.previewImg.src = result.imageData;
                    this.dom.previewImg.classList.remove('hidden');
                    this.dom.previewFallback.classList.add('hidden');
                }
            }

            if (this.state.studioMode && this.state.currentScene) {
                const result = await this.obs.call('GetSourceScreenshot', {
                    sourceName: this.state.currentScene,
                    imageFormat: 'jpeg',
                    imageWidth: 640,
                    imageHeight: 360,
                    imageCompressionQuality: 10
                });

                if (result.imageData) {
                    this.dom.programImg.src = result.imageData;
                    this.dom.programImg.classList.remove('hidden');
                    this.dom.programFallback.classList.add('hidden');
                }
            }
        } catch (err) {
            // Preview not available — that's OK
        }

        if (this.state.previewRunning) {
            requestAnimationFrame(() => this._runPreviewLoop());
        }
    }

    // ─── Stats Polling ───
    async _updateStats() {
        if (!this.state.connected) return;

        try {
            const stats = await this.obs.call('GetStats');
            const cpu = stats.cpuUsage?.toFixed(1) || '--';
            const fps = stats.activeFps?.toFixed(0) || '--';
            this.dom.obsStats.textContent = `CPU: ${cpu}% | FPS: ${fps}`;
        } catch {}

        // Update timecodes
        try {
            if (this.state.isStreaming) {
                const s = await this.obs.call('GetStreamStatus');
                this.dom.streamTimer.textContent = `⏱ ${this._formatTimecode(s.outputTimecode)}`;
            }
            if (this.state.isRecording) {
                const r = await this.obs.call('GetRecordStatus');
                this.dom.recordTimer.textContent = `⏺ ${this._formatTimecode(r.outputTimecode)}`;
            }
        } catch {}
    }

    _formatTimecode(tc) {
        if (!tc) return '00:00:00';
        // OBS returns format like "HH:MM:SS.mmm"
        return tc.split('.')[0] || tc;
    }

    // ─── Polling Control ───
    _startPolling() {
        this._stopPolling();
        this.state.previewRunning = true;
        this._runPreviewLoop();
        this.statsInterval = setInterval(() => this._updateStats(), 2000);
        this._updateStats();
    }

    _stopPolling() {
        this.state.previewRunning = false;
        if (this.statsInterval) {
            clearInterval(this.statsInterval);
            this.statsInterval = null;
        }
    }

    // ─── Modals & Management ───
    showModal(modalId) {
        const modal = this.dom[modalId];
        if (modal) modal.classList.remove('hidden');
    }

    hideModal(modalId) {
        const modal = this.dom[modalId];
        if (modal) modal.classList.add('hidden');
        
        if (modalId === 'modalAddScene') this.dom.newSceneName.value = '';
        if (modalId === 'modalAddSource') this.dom.newSourceName.value = '';
    }

    async _loadInputKinds() {
        try {
            const data = await this.obs.call('GetInputKindList');
            this.state.inputKinds = data.inputKinds || [];
            
            const select = this.dom.newSourceType;
            select.innerHTML = '';
            this.state.inputKinds.forEach(kind => {
                const opt = document.createElement('option');
                opt.value = kind;
                opt.textContent = kind;
                select.appendChild(opt);
            });
        } catch (err) {
            console.error('Error loading input kinds', err);
        }
    }

    async createScene() {
        const name = this.dom.newSceneName.value.trim();
        if (!name) return;
        
        try {
            await this.obs.call('CreateScene', { sceneName: name });
            this.hideModal('modalAddScene');
        } catch (err) {
            console.error('Error creating scene', err);
            alert('Error creating scene: ' + err.message);
        }
    }

    async createSource() {
        if (!this.state.currentScene) return;
        
        const name = this.dom.newSourceName.value.trim();
        const kind = this.dom.newSourceType.value;
        if (!name || !kind) return;
        
        try {
            await this.obs.call('CreateInput', {
                sceneName: this.state.currentScene,
                inputName: name,
                inputKind: kind,
                sceneItemEnabled: true
            });
            this.hideModal('modalAddSource');
            await this._loadSources();
        } catch (err) {
            console.error('Error creating source', err);
            alert('Error creating source: ' + err.message);
        }
    }

    // ─── UI State Transitions ───
    _showMainUI() {
        this.dom.overlay.classList.remove('active');
        this.dom.mainUI.classList.remove('hidden');
    }

    _showOverlay() {
        this.dom.mainUI.classList.add('hidden');
        this.dom.overlay.classList.add('active');

        // Reset preview
        this.dom.previewImg.classList.add('hidden');
        this.dom.previewFallback.classList.remove('hidden');
        this.dom.programImg.classList.add('hidden');
        this.dom.programFallback.classList.remove('hidden');
    }

    _setConnecting(loading) {
        this.dom.connectBtn.classList.toggle('connecting', loading);
        this.dom.connectBtnText.classList.toggle('hidden', loading);
        this.dom.connectBtnLoader.classList.toggle('hidden', !loading);
    }

    _showConnectError(msg) {
        this.dom.connectError.textContent = msg;
        this.dom.connectError.classList.remove('hidden');
    }

    _hideConnectError() {
        this.dom.connectError.classList.add('hidden');
    }

    // ─── Particles Animation ───
    _initParticles() {
        const container = document.getElementById('particles');
        for (let i = 0; i < 40; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.left = `${Math.random() * 100}%`;
            particle.style.animationDelay = `${Math.random() * 6}s`;
            particle.style.animationDuration = `${4 + Math.random() * 4}s`;

            const colors = ['#4fc3f7', '#7c4dff', '#00e676', '#ff9f43'];
            particle.style.background = colors[Math.floor(Math.random() * colors.length)];
            particle.style.width = `${2 + Math.random() * 3}px`;
            particle.style.height = particle.style.width;

            container.appendChild(particle);
        }
    }

    // ─── Utility ───
    _escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
}


// ─── Initialize ───
document.addEventListener('DOMContentLoaded', () => {
    window.obsController = new OBSController();
});
