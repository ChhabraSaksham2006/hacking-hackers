const fs = require('fs');
const path = require('path');

function walkDir(dir) {
    let results = [];
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
const rootFiles = walkDir('./frontend/src/routes');
const allFiles = [...new Set([...frontendFiles, ...serverFiles, ...rootFiles])];

let changed = 0;

// The exact corrupted string from the user's screenshot
const hindiCorrupted = "Flow à¤¦à¥ƒà¤·à¥\x8Dà¤Ÿà¤¿";
const hindiCorrupted2 = "Flow à¤¦à¥ƒà¤·à¥ à¤Ÿà¤¿";
const hindiCorrupted3 = "Flow à¤¦à¥ƒà¤·à¥\u008Dà¤Ÿà¤¿";

// The double-encoded arrow and interpunct
const dotCorrupted = "Â·";
const arrowCorrupted = "â†’";
// The weird powershell console output might just be how the console prints `à¤¦à¥ƒà¤·à¥à¤Ÿà¤¿`
// Let's just read the actual string from __root.tsx to see what it is
let rootContent = fs.readFileSync('./frontend/src/routes/__root.tsx', 'utf8');
let corruptedFlow = rootContent.match(/Flow [^\s"]+/)?.[0];
if (!corruptedFlow) {
  corruptedFlow = rootContent.match(/Flow [^\s<]+/)?.[0];
}

allFiles.forEach(file => {
    let content = fs.readFileSync(file, 'utf8');
    let originalContent = content;

    // Replace the specific mojibake
    if (corruptedFlow && corruptedFlow !== "Flow") {
       // Escape special regex chars
       const escaped = corruptedFlow.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
       content = content.replace(new RegExp(escaped, 'g'), 'Flow दृष्टि');
    }
    
    // Also blindly replace the known ones just in case
    content = content.replace(/Flow à¤¦à¥ƒà¤·à¥à¤Ÿà¤¿/g, 'Flow दृष्टि');
    content = content.replace(/Flow à¤¦à¥ƒà¤·à¥ à¤Ÿà¤¿/g, 'Flow दृष्टि');
    
    // Fix the dot and arrow that got corrupted by PowerShell Get-Content
    content = content.replace(/Â·/g, '·');
    content = content.replace(/â†’/g, '→');

    if (content !== originalContent) {
        fs.writeFileSync(file, content, 'utf8');
        changed++;
        console.log('Fixed encoding in: ' + file);
    }
});
console.log('Total files fixed: ' + changed);
