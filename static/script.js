const snippets = {
    sql_injection: `def get_user(db, username):\n    query = "SELECT * FROM users WHERE name = '" + username + "'"\n    return db.execute(query)`,
    
    command_injection: `import os\n\ndef ping_host(user_input):\n    os.system("ping -c 1 " + user_input)\n    return "Ping sent"`,
    
    weak_hash_and_secret: `import hashlib\n\nAPI_SECRET = "sk-live-12345abcde"\n\ndef store_password(password):\n    hashed = hashlib.md5(password.encode()).hexdigest()\n    return hashed`
};

const exampleSelect = document.getElementById('exampleSelect');
const codeInput = document.getElementById('code');
const languageSelect = document.getElementById('language');

// Auto-fill selected example into textarea
exampleSelect.addEventListener('change', (e) => {
    const selectedKey = e.target.value;
    if (snippets[selectedKey]) {
        codeInput.value = snippets[selectedKey];
        languageSelect.value = 'python';
    }
});

const form = document.getElementById('reviewForm');
const submitBtn = document.getElementById('submitBtn');
const resultsCard = document.getElementById('resultsCard');
const loadingText = document.getElementById('loadingText');
const errorMessage = document.getElementById('errorMessage');
const output = document.getElementById('output');

form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const code = codeInput.value;
    const language = languageSelect.value;

    resultsCard.classList.remove('hidden');
    loadingText.classList.remove('hidden');
    errorMessage.classList.add('hidden');
    output.textContent = '';
    submitBtn.disabled = true;

    try {
        const response = await fetch('/api/review', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: code, language: language })
        });

        if (!response.ok) {
            throw new Error(`Server error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        
        // Parse markdown text directly into HTML
        if (data.review) {
            output.innerHTML = marked.parse(data.review);
        } else {
            output.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
        }
    } catch (err) {
        errorMessage.textContent = `Error: ${err.message}`;
        errorMessage.classList.remove('hidden');
    } finally {
        loadingText.classList.add('hidden');
        submitBtn.disabled = false;
    }
});