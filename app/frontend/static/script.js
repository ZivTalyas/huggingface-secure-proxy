document.addEventListener('DOMContentLoaded', () => {
    const textInput = document.getElementById('text-input');
    const fileInput = document.getElementById('file-input');
    const uploadButton = document.getElementById('upload-button');
    const fileNameSpan = document.getElementById('file-name');
    const validateButton = document.getElementById('validate-button');
    const resultOutput = document.querySelector('#result-output code');
    const devToggle = document.getElementById('dev-toggle');
    const devDetails = document.getElementById('dev-details');
    const statusIndicator = document.getElementById('status-indicator');
    const resultOutputContainer = document.getElementById('result-output');
    const analysisResultContainer = document.getElementById('analysis-result');
    const securitySelector = document.getElementById('security-level-selector');

    let base64File = null;
    let currentSecurityLevel = 'high'; // Default security level

    // --- Backend Wake-up Logic ---
    const wakeUpBackend = async () => {
        validateButton.disabled = true;
        console.log('Checking backend status...');

        const performHealthCheck = async () => {
            try {
                const backendUrlResponse = await fetch('/get-backend-url');
                if (!backendUrlResponse.ok) throw new Error('Failed to get backend URL from frontend server.');
                const backendUrlData = await backendUrlResponse.json();
                const backendUrl = backendUrlData.url;
                if (!backendUrl) throw new Error('Backend URL not configured on frontend server.');

                const response = await fetch(`${backendUrl}/health`);
                return response.ok;
            } catch (error) {
                console.error('Health check failed:', error.message);
                return false;
            }
        };

        const handleSuccess = () => {
            statusIndicator.classList.add('hidden');
            resultOutputContainer.classList.remove('hidden');
            validateButton.disabled = false;
        };

        // Perform an initial, immediate check
        const isAlreadyAwake = await performHealthCheck();
        if (isAlreadyAwake) {
            console.log('Backend is already awake!');
            handleSuccess();
            return;
        }

        // If the initial check fails, start polling
        console.log('Backend not ready. Starting polling...');
        let retries = 10;
        const intervalId = setInterval(async () => {
            if (retries <= 0) {
                clearInterval(intervalId);
                statusIndicator.textContent = 'Could not connect to the server. Please try refreshing the page.';
                statusIndicator.style.color = 'var(--accent-color-dark)';
                return;
            }
            retries--;

            const isAwakeNow = await performHealthCheck();
            if (isAwakeNow) {
                clearInterval(intervalId);
                console.log('Backend has woken up!');
                handleSuccess();
            } else {
                console.log(`Still waiting for backend... ${retries} retries left.`);
            }
        }, 3000); // Poll every 3 seconds
    };
    
    // --- Event Listeners ---
    securitySelector.addEventListener('click', (e) => {
        if (e.target.tagName === 'BUTTON') {
            // Remove active class from all buttons
            securitySelector.querySelectorAll('.security-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            // Add active class to the clicked button
            e.target.classList.add('active');
            // Update the current security level
            currentSecurityLevel = e.target.dataset.level;
            console.log(`Security level set to: ${currentSecurityLevel}`);
        }
    });

    uploadButton.addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener('change', () => {
        const file = fileInput.files[0];
        if (file) {
            // Check file size (5MB limit)
            if (file.size > 5 * 1024 * 1024) {
                alert('File is too large. Maximum size is 5MB.');
                fileInput.value = ''; // Reset file input
                fileNameSpan.textContent = 'No file selected';
                base64File = null;
                return;
            }

            fileNameSpan.textContent = file.name;
            const reader = new FileReader();
            reader.onload = (e) => {
                base64File = e.target.result.split(',')[1];
            };
            reader.readAsDataURL(file);
        } else {
            fileNameSpan.textContent = 'No file selected';
            base64File = null;
        }
    });

    validateButton.addEventListener('click', async () => {
        const text = textInput.value;
        if (!text && !base64File) {
            alert('Please provide text or a file to analyze.');
            return;
        }

        analysisResultContainer.classList.remove('hidden');
        analysisResultContainer.innerHTML = `<div id="status-indicator">Analyzing...</div>`;

        try {
            const response = await fetch('/validate-input', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    text: text || null,
                    file: base64File,
                    security_level: currentSecurityLevel
                }),
            });
            const result = await response.json();
            displayFormattedResult(result);
        } catch (error) {
            analysisResultContainer.innerHTML = `<div class="result-reason">Error: Failed to fetch validation result.</div>`;
            console.error('Validation fetch error:', error);
        }
    });

    devToggle.addEventListener('click', () => {
        const isHidden = devDetails.classList.toggle('hidden');
        devToggle.setAttribute('aria-expanded', !isHidden);
        devToggle.innerHTML = isHidden ? 'Developer API &gt;' : 'Developer API &lt;';
    });

    // --- UI Update Functions ---
    const displayFormattedResult = (result) => {
        analysisResultContainer.innerHTML = ''; // Clear previous results
        analysisResultContainer.classList.remove('hidden');

        const isSafe = result.status === 'safe';
        const icon = isSafe 
            ? `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="result-title safe"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>`
            : `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="result-title unsafe"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>`;

        const createScoreBar = (label, score) => {
            const scorePercent = (score || 0) * 100;
            return `
                <div class="score-item">
                    <div class="score-label">
                        <span>${label}</span>
                        <span class="score-value">${scorePercent.toFixed(0)}%</span>
                    </div>
                    <div class="score-bar">
                        <div class="score-bar-inner" style="width: ${scorePercent}%;"></div>
                    </div>
                </div>
            `;
        };

        const resultHTML = `
            <div class="result-header">
                ${icon}
                <div>
                    <h2 class="result-title ${result.status}">${isSafe ? 'Analysis Complete: Safe' : 'Analysis Complete: Unsafe'}</h2>
                    <p class="result-reason">Reason: ${result.reason}</p>
                    ${!isSafe && result.analysis_summary ? `<p class="analysis-summary"><strong>Analysis Summary:</strong> ${result.analysis_summary}</p>` : ''}
                </div>
            </div>
            <div class="result-details">
                ${createScoreBar('Language Model Score', result.llm_score)}
                ${createScoreBar('Rule-Based Score', result.rule_score)}
                ${createScoreBar('Overall Risk Score', result.overall_score)}
            </div>
        `;

        analysisResultContainer.innerHTML = resultHTML;
    };

    // --- Initializations ---
    wakeUpBackend();
}); 