async function test() {
  const API_BASE = 'https://nurselink-frontend-8r6i.onrender.com';
  const res = await fetch(API_BASE + '/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'arjun@nurselink.in', password: 'password' })
  });
  const docLogin = await res.json();
  const token = docLogin.token;

  const pts = await fetch(API_BASE + '/patients', { headers: { 'Authorization': 'Bearer '+token } });
  const ptsData = await pts.json();
  
  const staff = await fetch(API_BASE + '/staff', { headers: { 'Authorization': 'Bearer '+token } });
  const staffData = await staff.json();

  console.log("=== RECENT PATIENTS ===");
  console.log(JSON.stringify(ptsData.slice(0,3), null, 2));

  console.log("=== STAFF ===");
  console.log(JSON.stringify(staffData, null, 2));
}
test();
