import urllib.request
import json
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

try:
    req = urllib.request.Request('https://nurselink-server.onrender.com/api/auth/login', 
        data=json.dumps({'email':'arjun@nurselink.in', 'password':'password'}).encode('utf-8'),
        headers={'Content-Type': 'application/json'})
    res = urllib.request.urlopen(req, context=ctx)
    token = json.loads(res.read())['token']

    req2 = urllib.request.Request('https://nurselink-server.onrender.com/api/patients', 
        headers={'Authorization': 'Bearer ' + token})
    res2 = urllib.request.urlopen(req2, context=ctx)
    pts = json.loads(res2.read())
    print("Number of patients:", len(pts))
    if len(pts) > 0:
        print(json.dumps(pts[0], indent=2))
except Exception as e:
    print(e)
