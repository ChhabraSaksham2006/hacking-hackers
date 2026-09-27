const fs = require('fs');

function cleanReplace(filePath) {
    let content = fs.readFileSync(filePath, 'utf8');
    
    // Replace standard occurrences
    content = content.replace(/Aegis Vantage/g, 'Flow दृष्टि');
    
    // Specifically handle the CSS classes or alt tags if there were lowercases
    content = content.replace(/aegis-vantage/g, 'flow-drishti');

    fs.writeFileSync(filePath, content, 'utf8');
}

cleanReplace('frontend/src/routes/__root.tsx');
cleanReplace('frontend/src/components/app/AppShell.tsx');
cleanReplace('frontend/src/components/app/AuthShell.tsx');
console.log('Clean replacement finished!');
