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

    let base64File = null;

    // --- Backend Wake-up Logic ---
    const wakeUpBackend = async () => {
        console.log('Attempting to wake up backend...');
        validateButton.disabled = true;

        const maxRetries = 10;
        let attempt = 0;

        const intervalId = setInterval(async () => {
            attempt++;
            if (attempt > maxRetries) {
                clearInterval(intervalId);
                statusIndicator.textContent = 'Could not connect to the server. Please try refreshing the page.';
                statusIndicator.style.color = '#dc3545';
                return;
            }

            try {
                // The BACKEND_URL is now accessed via this special endpoint.
                const backendUrlResponse = await fetch('/get-backend-url');
                const backendUrlData = await backendUrlResponse.json();
                const backendUrl = backendUrlData.url;

                if (!backendUrl) {
                    throw new Error("Backend URL not configured.");
                }

                const response = await fetch(`${backendUrl}/health`);
                
                if (response.ok) {
                    clearInterval(intervalId);
                    console.log('Backend is awake!');
                    statusIndicator.classList.add('hidden');
                    resultOutputContainer.classList.remove('hidden');
                    validateButton.disabled = false;
                } else {
                    console.log(`Backend not ready yet (attempt ${attempt})...`);
                }
            } catch (error) {
                console.error(`Wake-up attempt ${attempt} failed:`, error);
            }
        }, 3000); // Retry every 3 seconds
    };
    
    // --- Event Listeners ---
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
            resultOutput.textContent = JSON.stringify({ error: 'Please provide text or a file.' }, null, 2);
            return;
        }

        resultOutput.textContent = 'Validating...';

        try {
            const response = await fetch('/validate-input', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    text: text || null,
                    file: base64File,
                    security_level: 'high'
                }),
            });

            const result = await response.json();
            resultOutput.textContent = JSON.stringify(result, null, 2);

        } catch (error) {
            resultOutput.textContent = JSON.stringify({ error: 'Failed to fetch validation result.', details: error.message }, null, 2);
        }
    });

    devToggle.addEventListener('click', () => {
        const isHidden = devDetails.classList.toggle('hidden');
        devToggle.setAttribute('aria-expanded', !isHidden);
        devToggle.innerHTML = isHidden ? 'Developer API &gt;' : 'Developer API &lt;';
    });

    // --- Initializations ---
    wakeUpBackend();
}); 