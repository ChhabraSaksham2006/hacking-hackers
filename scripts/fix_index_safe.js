const fs = require('fs');

let content = fs.readFileSync('frontend/src/routes/index.tsx', 'utf8');

content = content.replace(/Flow \?\?\?\?\?\?/g, 'Flow दृष्टि');
content = content.replace(/Flow à¤¦à¥ƒà¤·à¥ à¤Ÿà¤¿/g, 'Flow दृष्टि');
content = content.replace(/Flow  ݅ \? Y  \?/g, 'Flow दृष्टि');
content = content.replace(/Flow  ݅ \? Y  \?/g, 'Flow दृष्टि');
content = content.replace(/Flow  ݅ \? Y /g, 'Flow दृष्टि');

content = content.replace(/â€”/g, '—');
content = content.replace(/Â·/g, '·');
content = content.replace(/â†’/g, '→');
content = content.replace(/Ac 2026/g, '© 2026');

fs.writeFileSync('frontend/src/routes/index.tsx', content, 'utf8');
console.log('Fixed index.tsx specifically and safely');
