from ring_doorbell_tools import Ring
import json
from extronlib.system import File
from extronlib import event

#with File('creds.json', mode='wt') as file:
    #file.write(json.dumps({'username': 'myusername@email.com', 'password': 'secrepassw0rd'}))

try:
    with File('creds.json', mode='rt') as file:
        d = json.loads(file.read())
        username = d.get('username', None)
        password = d.get('password', None)
    print('username=', username)
    print('password=', '*' * len(password))
except Exception as e:
    print('No Username/password found:', e)
    username = None
    password = None

ring = Ring(
    username,
    password
    )


@event(ring, ['Connected', 'Disconnected'])
def ConnectionEvent(interface, state):
    print('ConnectionEvent(interface={}, state={})'.format(interface, state))


@event(ring, 'Motion')
def MotionEvent(deviceName, evt):
    print('MotionEvent(deviceName={}, evt={})'.format(deviceName, evt))


@event(ring, 'Ding')
def DingEvent(deviceName, evt):
    print('DingEvent(deviceName={}, evt={})'.format(deviceName, evt))


@event(ring, 'Other')
def OtherEvent(deviceName, evt):
    print('OtherEvent(deviceName={}, evt={})'.format(deviceName, evt))


print('End main.py. Waiting for new events...')
