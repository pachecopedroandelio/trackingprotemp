import os, time, secrets, hmac, json, urllib.request, urllib.parse, urllib.error
from flask import Flask, request, jsonify, render_template, redirect, session
from werkzeug.middleware.proxy_fix import ProxyFix

app=Flask(__name__)
app.secret_key=os.environ.get('SESSION_SECRET', secrets.token_hex(32))
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=os.getenv('LOCAL_DEV')!='1', SESSION_COOKIE_SAMESITE='Lax', PERMANENT_SESSION_LIFETIME=3600)
app.wsgi_app=ProxyFix(app.wsgi_app,x_proto=1,x_host=1)
BASE='https://i-cloud.tzonedigital.com'
cache={'token':None,'until':0}

def api(path, params=None, token=None):
    url=BASE+path
    if params: url+='?'+urllib.parse.urlencode(params)
    headers={'Accept':'application/json','User-Agent':'ProTemp-V4/1.0'}
    if token: headers['Authorization']='Bearer '+token
    req=urllib.request.Request(url,headers=headers)
    try:
        with urllib.request.urlopen(req,timeout=20) as r: return r.status,json.loads(r.read(2_000_000))
    except urllib.error.HTTPError as e: return e.code, {'status':'upstream_error'}
    except (TimeoutError,urllib.error.URLError,ValueError): return 502, {'status':'connection_error'}

def token():
    if cache['token'] and cache['until']>time.time()+120: return cache['token']
    keys=[os.getenv(k) for k in ('TZONE_APP_ID','TZONE_APP_KEY','TZONE_APP_SECRET')]
    if not all(keys): return None
    code,data=api('/Identity',dict(zip(('appId','appKey','appSecret'),keys)))
    body=data.get('body') if isinstance(data,dict) else None
    result=body.get('token') if isinstance(body,dict) else None
    if code==200 and result:
        cache.update(token=result,until=time.time()+45*60)
        return result
    return None

def authenticated(): return bool(session.get('admin'))

@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Cache-Control']='no-store'
    response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self' https://unpkg.com; script-src 'self' https://unpkg.com; img-src 'self' data: https://unpkg.com https://*.arcgisonline.com https://*.openstreetmap.org https://*.tile.openstreetmap.org; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    return response

@app.get('/health')
def health(): return jsonify(status='ok')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        configured=os.getenv('ADMIN_PASSWORD','')
        provided=request.form.get('password','')
        if configured and hmac.compare_digest(configured,provided):
            session.clear(); session['admin']=True; session.permanent=True
            return redirect('/')
        return render_template('login.html',error='Invalid password'),401
    return render_template('login.html',error=None)

@app.post('/logout')
def logout(): session.clear(); return redirect('/login')

@app.get('/')
def index():
    if not authenticated(): return redirect('/login')
    return render_template('dashboard.html')

@app.get('/api/devices')
def devices():
    if not authenticated(): return jsonify(error='Unauthorized'),401
    t=token()
    if not t: return jsonify(error='TZONE authentication unavailable. Check Render environment variables.'),502
    out=[]
    # Fetch successive pages, capped to keep this administrator pilot bounded.
    for page in range(1,21):
        code,data=api('/Device',{'pageIndex':page,'pageSize':100},t)
        if code!=200 or not isinstance(data,dict): return jsonify(error='Unable to fetch devices'),502
        body=data.get('body') or {}
        rows=body.get('dataList',[]) if isinstance(body,dict) else []
        if not isinstance(rows,list): return jsonify(error='Unexpected device response'),502
        for d in rows:
            if isinstance(d,dict) and d.get('id') is not None:
                out.append({'id':d['id'],'name':d.get('deviceName') or d.get('deviceID') or 'Unnamed device','status':d.get('statusType'),'address':d.get('address')})
        if len(rows)<100: break
    return jsonify(devices=out,count=len(out),truncated=len(out)>=2000)

@app.get('/api/realtime/<int:device_id>')
def realtime(device_id):
    if not authenticated(): return jsonify(error='Unauthorized'),401
    t=token()
    if not t: return jsonify(error='TZONE authentication unavailable'),502
    # Validate against device IDs returned by the authenticated TZONE account.
    found=False
    for page in range(1,21):
        c,d=api('/Device',{'pageIndex':page,'pageSize':100},t)
        if c!=200 or not isinstance(d,dict): return jsonify(error='Device authorization unavailable'),502
        body=d.get('body') or {}
        allowed=body.get('dataList',[]) if isinstance(body,dict) else []
        if not isinstance(allowed,list): return jsonify(error='Device authorization unavailable'),502
        if any(str(x.get('id'))==str(device_id) for x in allowed if isinstance(x,dict)):
            found=True
            break
        if len(allowed)<100: break
    if not found: return jsonify(error='Device not available in current account'),404
    code,raw=api('/Data/Realtime/'+str(device_id),token=t)
    if code!=200: return jsonify(error='Unable to fetch realtime data'),502
    b=raw.get('body') if isinstance(raw,dict) else None
    if not isinstance(b,dict): return jsonify(error='Unexpected telemetry response'),502
    fields=('temperature','temperature1','humidity','battery','rssi','latLng','address','dateTime','time','light','vibration','isOnline')
    return jsonify(reading={k:b.get(k) for k in fields if k in b})

if __name__=='__main__': app.run(host='127.0.0.1',port=5000,debug=False)
