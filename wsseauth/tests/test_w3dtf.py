from datetime import *

from wsseauth import parse_w3dtf

def test_w3dtf():
    
    d1 = '2007-07-16T15:46:07.507379Z'
    d2 = '2007-07-16T05:16:07.507379+10:30'

    expected = datetime(2007, 7, 16, 15, 46, 7) #that's the expected utc time
    local_timezone_offset = datetime.utcnow() - datetime.now() #.. or so
    expected_local = expected - local_timezone_offset
    assert parse_w3dtf(d1) - expected_local < timedelta(0,1,0)
    assert parse_w3dtf(d2) - expected_local < timedelta(0,1,0) 
