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

    // Fix the em-dash mojibake and others
    content = content.replace(/â€”/g, '—');
    content = content.replace(/Â·/g, '·');
    content = content.replace(/â†’/g, '→');
    content = content.replace(/ðŸ”´/g, '🔴');
    content = content.replace(/ðŸ›¡ï¸/g, '🛡️');
    
    // Also, if "Flow दृष्टि" got changed to "Flow Drishti" in some places and we want to ensure everything is perfect
    
    if (content !== original) {
        fs.writeFileSync(file, content, 'utf8');
        changed++;
        console.log('Successfully fixed mojibake in: ' + file);
    }
});
console.log('Total files fixed: ' + changed);
