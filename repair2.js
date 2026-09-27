const fs = require('fs');

function fixFile(file) {
    if (!fs.existsSync(file)) return;
    let content = fs.readFileSync(file, 'utf8');
    
    // Replace anything that is 'Flow ' followed by garbage that spans until a known word or end of phrase
    content = content.replace(/Flow[\s\S]*?Predictive/g, 'Flow दृष्टि — Predictive');
    content = content.replace(/Flow[\s\S]*?forecasts/g, 'Flow दृष्टि forecasts');
    content = content.replace(/Flow[\s\S]*?runs a/g, 'Flow दृष्टि runs a');
    
    // In AppShell and others
    content = content.replace(/Flow <span className="text-teal font-sans">[\s\S]*?<\/span>/g, 'Flow <span className="text-teal font-sans">दृष्टि</span>');
    content = content.replace(/alt="Flow[\s\S]*?"/g, 'alt="Flow दृष्टि"');
    content = content.replace(/title="Flow[\s\S]*?Dashboard"/g, 'title="Flow दृष्टि Dashboard"');
    
    // Fix explorer link in AppShell
    content = content.replace(/Flow  explorer/g, 'Flow explorer');
    
    fs.writeFileSync(file, content, 'utf8');
    console.log('Fixed ' + file);
}

fixFile('./frontend/src/routes/__root.tsx');
fixFile('./frontend/src/routes/index.tsx');
fixFile('./frontend/src/components/app/AppShell.tsx');
fixFile('./frontend/src/components/app/AuthShell.tsx');
