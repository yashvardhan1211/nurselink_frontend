const fs = require('fs');
let file = 'index.html';
let content = fs.readFileSync(file, 'utf8');

// Replace function
content = content.replace(/function markNotifRead\(id\) \{\s*const n = S\.notifications\.find\(x=>x\.id===id\);\s*if \(n\) n\.read = true;\s*\}/, 
`function handleNotifClick(id) {
  const n = S.notifications.find(x=>x.id===id);
  if (n) {
    n.read = true;
    document.getElementById('notif-dropdown').style.display = 'none';
    if (n.pid) openPatient(n.pid);
  }
  renderNotifBadge();
}`);

// Replace div clicks
content = content.replace(/onclick="markNotifRead\('\$\{n\.id\}'\)"/g, `onclick="handleNotifClick('${n.id}')"`);

// Inject pid to all notifications safely
content = content.replace(/(S\.notifications\.unshift\(\{\s*id:'N'\+Date\.now\(\),\s*role:[^,]+,)\s*title/g, 
  (match, p1) => p1 + " pid: (typeof pid !== 'undefined' ? pid : (typeof p !== 'undefined' ? p?.id : (typeof data !== 'undefined' ? data.patientId : (typeof lab !== 'undefined' ? lab.patientId : null)))), title"
);

fs.writeFileSync(file, content);
console.log('Fixes applied successfully!');
