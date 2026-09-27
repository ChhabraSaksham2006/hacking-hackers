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

    // 1. Fix the PowerShell double-encoded interpunct and arrow
    content = content.replace(/Â·/g, '·');
    content = content.replace(/â†’/g, '→');
    content = content.replace(/Â/g, ''); // just in case isolated Â exists from other double encoding

    // 2. Fix the Mojibake Hindi
    // In some files it's exactly "Flow à¤¦à¥ƒà¤·à¥ à¤Ÿà¤¿" or similar
    content = content.replace(/Flow à¤¦à¥ƒà¤·à¥[^\s]*à¤Ÿà¤¿/g, 'Flow दृष्टि');
    content = content.replace(/Flow à¤¦à¥ƒà¤·à¥\s*à¤Ÿà¤¿/g, 'Flow दृष्टि');
    
    // In __root.tsx it's "Flow  ݅ ? Y  ?"
    // Let's just find anything starting with "Flow " and ending with " Predictive"
    content = content.replace(/Flow.*?Predictive/g, 'Flow दृष्टि — Predictive');
    
    // And for description "Flow ... forecasts"
    content = content.replace(/Flow.*?forecasts/g, 'Flow दृष्टि forecasts');

    // And in index.tsx: "Flow ...runs a"
    content = content.replace(/Flow.*?runs a/g, 'Flow दृष्टि runs a');
    
    // And in Dashboard.tsx, it might have "Flow ???"
    content = content.replace(/Flow \?\?\?\?\?\?/g, 'Flow दृष्टि');

    // Make sure we didn't accidentally replace normal stuff
    // Let's just normalize multiple spaces just in case
    
    if (content !== original) {
        fs.writeFileSync(file, content, 'utf8');
        changed++;
        console.log('Fixed mojibake in: ' + file);
    }
});
console.log('Total files repaired: ' + changed);
