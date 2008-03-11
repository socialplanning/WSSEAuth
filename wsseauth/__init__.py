from sha import sha
import re
from datetime import datetime, timedelta
from wsseauth.fifo import Fifo

from random import random
from simplejson import dumps

w3dtf_re = re.compile("(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}(?:\.\d+)?)(?:(Z)|([+-])(\d{2}):(\d{2}))")
local_timezone_offset = datetime.utcnow() - datetime.now() #it's approximate, but so what?  Python's datetime libraries are such shit.

def parse_w3dtf(w3dtf):
    results = w3dtf_re.match(w3dtf)
    y = int(results.group(1))
    mo = int(results.group(2))
    d = int(results.group(3))
    h = int(results.group(4))
    mi = int(results.group(5))    
    s = float(results.group(6))
    frac = s - int(s)
    s = int(s)
    utc = bool(results.group(7))
    tz_adj_h = 0
    tz_adj_m = 0
    if not utc:
        neg = results.group(8) == "-"
        tz_adj_h = int(results.group(9))
        tz_adj_m = int(results.group(10))
        if neg: 
            tz_adj_h = -tz_adj_h
            tz_adj_m = -tz_adj_m
    date = datetime(y, mo, d, h, mi, s, int(frac * 100000))
    #convert from given tz to UTC
    date -= timedelta(0, 0, 0, 0, tz_adj_m, tz_adj_h)
    #convert from UTC to local time
    date -= local_timezone_offset 
    return date

class WSSEAuthMiddleware:
    def __init__(self, app, user_dict, required = False, json=True):
        self.app = app
        self.user_dict = user_dict
        self.nonces_by_time = Fifo()
        self.nonces_set = set()
        self.required = required
        self.json = json
        
    def _fail(self, start_response):
        status = "401 Authorization Required"
        headers = [('Content-type', 'text/plain'), ('WWW-Authenticate', 'WSSE realm="wsse", profile="UsernameToken"')]
        start_response(status, headers)
        if self.json:
            return [dumps({'status' : 'rejected', 'reason' : 'Bad WSSE Auth'})]
        else:
            return ['Bad WSSE Auth']
            
    def __call__(self, environ, start_response):
        #parse nonce, created, username out of ...
        #check validity of wsse info

        if environ.get('HTTP_AUTHORIZATION', None) != 'WSSE profile="UsernameToken"':
            if self.required:
                #print "no http_auth", environ
                return self._fail(start_response)
            else:
                return self.app(environ, start_response)

        header = environ.get('HTTP_X_WSSE', None)
        if not header:
            #print "no header"
            return self._fail(start_response)            
        
        wsse_re = re.compile('UsernameToken Username="([^"]+)", PasswordDigest="([^"]+)", Nonce="([^"]+)", Created="([^"]+)"')
        match = wsse_re.match(header)
        if not match:
            #print "Bad format"
            return self._fail(start_response) #bad format

        username = match.group(1)
        password = self.user_dict.get(username.lower())
        if not password:
            #print "no user %s password" % username
            return self._fail(start_response)
        digest = match.group(2)
        nonce = match.group(3)
        created = match.group(4)

        if nonce in self.nonces_set:
            #print "already used this nonce"
            return self._fail(start_response)

        created_date = parse_w3dtf(created)
        five_minutes_ago = datetime.now() - timedelta(0, 300, 0)
        if created_date < five_minutes_ago:
            #print "too old"
            return self._fail(start_response) #too old

        self.nonces_set.add(nonce)

        self.nonces_by_time.append((created_date, nonce))

        #remove old nonces
        while not self.nonces_by_time.empty() and self.nonces_by_time.top()[0] < five_minutes_ago:
            created_date, nonce = self.nonces_by_time.pop()
            nonces_set.remove(nonce)

        key = "%s%s%s" % (nonce, created, password)        
        if not digest == sha(key).digest().encode("base64").strip():
            #print "did not match"
            return self._fail(start_response)

        environ['REMOTE_USER'] = username
        environ['AUTHENTICATION_METHOD'] = 'WSSE'
        return self.app(environ, start_response)

def wsse_header(username, password):
    hexdigits = "0123456789abcdef"
    nonce = "".join(hexdigits[int(random() * 16)] for x in range(32))
    created = datetime.utcnow().isoformat() + "Z"
    password_digest = "%s%s%s" % (nonce, created, password)
    password_digest = sha(password_digest).digest().encode("base64").strip()
    
    header = 'UsernameToken Username="%s", PasswordDigest="%s", Nonce="%s", Created="%s"' % (username, password_digest, nonce, created)
    return header
