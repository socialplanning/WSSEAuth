from sha import sha
import paste.fixture
from wsseauth import WSSEAuthMiddleware
from random import random
from datetime import datetime, timedelta

def wsgi_app(environ, start_response):
    start_response('200 OK', [('content-type', 'text/html')])
    return ['Hello, ', environ.get('REMOTE_USER', 'Anonymous Coward')]

def gen_auth(username, password):
    hexdigits = "0123456789abcdef"
    nonce = "".join(hexdigits[int(random() * 16)] for x in range(32))
    created = datetime.utcnow().isoformat() + "Z"
    password_digest = "%s%s%s" % (nonce, created, 'airplane')
    password_digest = sha(password_digest).digest().encode("base64")
    return 'UsernameToken Username="%s", PasswordDigest="%s", Nonce="%s", Created="%s"' % (username, password_digest, nonce, created)

def test_working():
    users = {'jefferson' : 'airplane'}

    wsse_app = WSSEAuthMiddleware(wsgi_app, users)


    test_app = paste.fixture.TestApp(wsse_app, extra_environ={
        'HTTP_AUTHORIZATION': 'WSSE profile="UsernameToken"',
        'HTTP_X_WSSE' : gen_auth('jefferson', 'airplane')
        })

    test_app.get('/').mustcontain('Hello, jefferson')

def test_required():
    users = {'jefferson' : 'airplane'}

    wsse_app = WSSEAuthMiddleware(wsgi_app, users, required=True)

    test_app = paste.fixture.TestApp(wsse_app)

    result = test_app.get('/', status=401)

    test_app = paste.fixture.TestApp(wsse_app, extra_environ={
        'HTTP_AUTHORIZATION': 'WSSE profile="UsernameToken"',
        'HTTP_X_WSSE' : gen_auth('jefferson', 'airplane')
        })

    test_app.get('/').mustcontain('Hello, jefferson')
    
def test_nologin():
    users = {'jefferson' : 'airplane'}

    wsse_app = WSSEAuthMiddleware(wsgi_app, users)
    test_app = paste.fixture.TestApp(wsse_app)

    test_app.get('/').mustcontain('Hello, Anonymous Coward')


def test_old():
    users = {'jefferson' : 'airplane'}
    username = 'jefferson'
    password = 'airplane'
    
    created = datetime.utcnow() - timedelta(0, 500, 0) #too long ago
    
    hexdigits = "0123456789abcdef"
    nonce = "".join(hexdigits[int(random() * 16)] for x in range(32))
    created = created.isoformat() + "Z"
    password_digest = "%s%s%s" % (nonce, created, password)
    password_digest = sha(password_digest).digest().encode("base64")
    auth =  'UsernameToken Username="%s", PasswordDigest="%s", Nonce="%s", Created="%s"' % (username, password_digest, nonce, created)

    wsse_app = WSSEAuthMiddleware(wsgi_app, users)
    test_app = paste.fixture.TestApp(wsse_app, extra_environ={
        'HTTP_AUTHORIZATION': 'WSSE profile="UsernameToken"',
        'HTTP_X_WSSE' : auth
        })

    #login failed
    test_app.get('/', status=401)

def test_bad_digest():
    users = {'jefferson' : 'airplane'}
    
    wsse_app = WSSEAuthMiddleware(wsgi_app, users)

    #bad format
    test_app = paste.fixture.TestApp(wsse_app, extra_environ={
        'HTTP_AUTHORIZATION': 'WSSE profile="UsernameToken"',
        'HTTP_X_WSSE' : 'thisisaverybadauth'
        })

    test_app.get('/', status=401)
    
    hexdigits = "0123456789abcdef"
    nonce = "".join(hexdigits[int(random() * 16)] for x in range(32))
    created = datetime.utcnow().isoformat() + "Z"
    password_digest = "%s%s%s" % (nonce, created, 'airplane')
    password_digest = sha(password_digest).digest().encode("base64")
    auth =  'UsernameToken Username="%s", PasswordDigest="%sbogus", Nonce="%s", Created="%s"' % ('jefferson', password_digest, nonce, created)

    test_app = paste.fixture.TestApp(wsse_app, extra_environ={
        'HTTP_AUTHORIZATION': 'WSSE profile="UsernameToken"',
        'HTTP_X_WSSE' : auth
        })


    test_app.get('/', status=401)

