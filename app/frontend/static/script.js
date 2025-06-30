document.addEventListener('DOMContentLoaded', () => {
    const textInput = document.getElementById('text-input');
    const fileInput = document.getElementById('file-input');
    const uploadButton = document.getElementById('upload-button');
    const fileNameSpan = document.getElementById('file-name');
    const validateButton = document.getElementById('validate-button');
    const resultOutput = document.querySelector('#result-output code');
    const devToggle = document.getElementById('dev-toggle');
    const devDetails = document.getElementById('dev-details');

    let base64File = null;

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
        devDetails.classList.toggle('hidden');
        devToggle.textContent = devDetails.classList.contains('hidden') ? 'API for Developers >' : 'API for Developers <';
    });
}); 