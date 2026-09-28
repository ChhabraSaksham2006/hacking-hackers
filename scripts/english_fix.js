const fs = require('fs');
const path = require('path');

function walkDir(dir) {
    let results = [];
    if (!fs.existsSync(dir)) return results;
    const list = fs.readdirSync(dir);
    list.forEach(function(file) {
        file = path.join(dir, file);
        const stat = fs.statSync(file);
        if (stat && stat.isDirectory()) {
            if (!file.includes('node_modules') && !file.includes('dist') && !file.includes('.git') && !file.includes('.vercel')) {
                results = results.concat(walkDir(file));
            }
        } else {
            if (file.endsWith('.tsx') || file.endsWith('.ts') || file.endsWith('.css') || file.endsWith('.md')) {
                results.push(file);
            }
        }
    });
    return results;
}

const frontendFiles = walkDir('./frontend/src');
const serverFiles = walkDir('./server/src');
const allFiles = [...frontendFiles, ...serverFiles];

let changed = 0;

allFiles.forEach(file => {
    let content = fs.readFileSync(file, 'utf8');
    let original = content;

    // Replace EVERYTHING with "Flow Drishti" in plain English
    content = content.replace(/Aegis Vantage/g, 'Flow Drishti');
    content = content.replace(/Flow दृष्टि/g, 'Flow Drishti');
    content = content.replace(/Flow à¤¦à¥ƒà¤·à¥[^\s]*à¤Ÿà¤¿/g, 'Flow Drishti');
    content = content.replace(/Flow à¤¦à¥ƒà¤·à¥\s*à¤Ÿà¤¿/g, 'Flow Drishti');
    content = content.replace(/Flow  ݅ \? Y  \?/g, 'Flow Drishti');
    content = content.replace(/Flow \?\?\?\?\?\?/g, 'Flow Drishti');
    content = content.replace(/Flow  ݅ \? Y /g, 'Flow Drishti');
    content = content.replace(/Flow à¤¦à¥ƒà¤·à¥ à¤Ÿà¤¿/g, 'Flow Drishti');
    content = content.replace(/Flow <span className=\"text-teal font-sans\">दृष्टि<\/span>/g, 'Flow <span className=\"text-teal font-sans\">Drishti<\/span>');
    content = content.replace(/aegis-vantage/g, 'flow-drishti');
    
    // Fix the logo in AppShell / AuthShell
    content = content.replace(/Flow <span className=\"text-teal font-sans\"> ݅ \? Y <\/span>/g, 'Flow <span className=\"text-teal font-sans\">Drishti<\/span>');

    // Fix other random unicode mojibakes for the logo if any exist
    content = content.replace(/Flow <span className=\"text-teal font-sans\">[^<]+<\/span>/g, 'Flow <span className=\"text-teal font-sans\">Drishti<\/span>');

    if (content !== original) {
        fs.writeFileSync(file, content, 'utf8');
        changed++;
        console.log('Successfully set to English: ' + file);
    }
});
console.log('Total files fixed to English: ' + changed);
