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
const serverEnvFiles = ['./server/.env', './server/.env.example'].filter(f => fs.existsSync(f));
const allFiles = [...frontendFiles, ...serverFiles, ...serverEnvFiles];

let changed = 0;

allFiles.forEach(file => {
    let content = fs.readFileSync(file, 'utf8');
    let original = content;
    
    content = content.replace(/Aegis Vantage/g, 'Flow दृष्टि');
    // For anything that was strictly lower-case, we can leave it (like email domain)
    // Or we replace Aegis standalone
    
    if (content !== original) {
        fs.writeFileSync(file, content, 'utf8');
        changed++;
        console.log('Successfully updated: ' + file);
    }
});
console.log('Total files safely re-branded: ' + changed);
