document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('urlInput');
    const textInput = document.getElementById('textInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const btnText = document.querySelector('.btn-text');
    const spinner = document.getElementById('loadingSpinner');
    
    const resultsSection = document.getElementById('resultsSection');
    const scoreCircle = document.getElementById('scoreCircle');
    const trustScoreValue = document.getElementById('trustScoreValue');
    const riskBadge = document.getElementById('riskBadge');
    const explanationText = document.getElementById('explanationText');

    analyzeBtn.addEventListener('click', async () => {
        const url = urlInput.value.trim();
        const text = textInput.value.trim();

        if (!url || !text) {
            alert('Please enter both a URL and the message content.');
            return;
        }

        // UI Loading State
        analyzeBtn.disabled = true;
        btnText.textContent = 'Analyzing Threat...';
        spinner.classList.remove('hidden');
        
        // Hide old results immediately
        resultsSection.classList.remove('show');
        resultsSection.className = 'results-card hidden';
        scoreCircle.setAttribute('stroke-dasharray', `0, 100`);
        trustScoreValue.textContent = '0';

        try {
            const response = await fetch('http://localhost:8000/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url, text })
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => null);
                throw new Error(errorData?.detail || 'Failed to connect to the backend API. Is it running?');
            }

            const data = await response.json();
            
            // Set Risk Label & Color classes
            riskBadge.textContent = data.risk;
            if (data.risk === 'Safe') {
                resultsSection.classList.add('status-safe');
            } else if (data.risk === 'Suspicious') {
                resultsSection.classList.add('status-suspicious');
            } else {
                resultsSection.classList.add('status-dangerous');
            }

            // Set Explanation
            explanationText.textContent = data.explanation;

            // Show Results with animation
            resultsSection.classList.remove('hidden');
            // Small delay to trigger CSS transition smoothly
            setTimeout(() => {
                resultsSection.classList.add('show');
                animateScore(data.trust_score);
            }, 50);

        } catch (error) {
            alert(`Error: ${error.message}`);
        } finally {
            // Restore UI
            analyzeBtn.disabled = false;
            btnText.textContent = 'Analyze Threat Level';
            spinner.classList.add('hidden');
        }
    });

    function animateScore(targetScore) {
        let currentScore = 0;
        const duration = 1500; // ms
        const interval = 20;
        const steps = duration / interval;
        const increment = targetScore / steps;

        // Animate SVG Circle stroke
        setTimeout(() => {
            scoreCircle.setAttribute('stroke-dasharray', `${targetScore}, 100`);
        }, 100);

        // Animate Number ticking up
        const counter = setInterval(() => {
            currentScore += increment;
            if (currentScore >= targetScore) {
                currentScore = targetScore;
                clearInterval(counter);
            }
            trustScoreValue.textContent = Math.round(currentScore);
        }, interval);
    }
});
