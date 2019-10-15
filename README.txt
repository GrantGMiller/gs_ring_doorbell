import creds

ring = Ring(creds.username, creds.password)


@event(ring, ['Connected', 'Disconnected'])
def ConnectionEvent(interface, state):
    print('ConnectionEvent(interface={}, state{})'.format(interface, state))


@event(ring, 'Motion')
def MotionEvent(deviceName, evt):
    print('MotionEvent(deviceName={}, evt={})'.format(deviceName, evt))


@event(ring, 'Ding')
def DingEvent(deviceName, evt):
    print('DingEvent(deviceName={}, evt={})'.format(deviceName, evt))


@event(ring, 'Other')
def OtherEvent(deviceName, evt):
    print('OtherEvent(deviceName={}, evt={})'.format(deviceName, evt))
