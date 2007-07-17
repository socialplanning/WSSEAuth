from sha import sha
import paste.fixture
from wsseauth import WSSEAuthMiddleware
from random import random
from datetime import datetime

def test_app(environ, start_response):
    start_response('200 OK', [('content-type', 'text/html')])
    return ['Hello, ', environ.get('REMOTE_USER', 'Anonymous Coward')]

users = {'jefferson' : 'airplane'}

wsse_app = WSSEAuthMiddleware(test_app, users)

hexdigits = "0123456789abcdef"
nonce = "".join(hexdigits[int(random() * 16)] for x in range(32))
created = datetime.utcnow().isoformat() + "Z"
password_digest = "%s%s%s" % (nonce, created, 'airplane')
password_digest = sha(password_digest).digest().encode("base64")

test_app = paste.fixture.TestApp(wsse_app, extra_environ={
    'HTTP_AUTHORIZATION': 'WSSE profile="UsernameToken"',
    'HTTP_X_WSSE' : 'UsernameToken Username="jefferson", PasswordDigest="%s", Nonce="%s", Created="%s"' % (password_digest, nonce, created)
    })

test_app.get('/').mustcontain('Hello, jefferson')
