const fs = require('fs');
let content = fs.readFileSync('frontend/src/routes/index.tsx', 'utf8');

// Fix pageHead string
content = content.replace(/\"Flow[^\"]+\" Cyber World Model Defense\"/g, '\"Flow दृष्टि — Cyber World Model Defense\"');

// Fix alt text
content = content.replace(/alt=\"Flow[^\"]+\"/g, 'alt=\"Flow दृष्टि\"');

// Fix title text
content = content.replace(/Flow <span className=\"text-teal font-sans\">[^<]+<\/span>/g, 'Flow <span className=\"text-teal font-sans\">दृष्टि</span>');

// Fix body text
content = content.replace(/Flow \?\?\?\?\?\? runs a/g, 'Flow दृष्टि runs a');
content = content.replace(/Flow \?\?\?\?\?\? encodes/g, 'Flow दृष्टि encodes');
content = content.replace(/Flow \?\?\?\?\?\? flagged/g, 'Flow दृष्टि flagged');

// Fix comments or other tags
content = content.replace(/Flow [^\s\*]+ World Model/g, 'Flow दृष्टि World Model');

// Fix copyright
content = content.replace(/2026 Flow [^\.]+./g, '2026 Flow दृष्टि.');

// Fix interpunct
content = content.replace(/A 20.0s/g, '· 20.0s');
content = content.replace(/Ac 2026/g, '© 2026');
content = content.replace(/A 20.0s/g, '· 20.0s');

fs.writeFileSync('frontend/src/routes/index.tsx', content, 'utf8');
console.log('Fixed index.tsx safely.');
