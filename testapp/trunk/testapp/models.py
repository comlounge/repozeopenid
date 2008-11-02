from zope.interface import Interface
from zope.interface import implements

class IMyModel(Interface):
    pass

from repoze.bfg.security import Everyone, Authenticated
from repoze.bfg.security import Allow

class MyModel(object):
    implements(IMyModel)

    __acl__ = [
	(Allow, Authenticated, 'view'),
    ]
    pass

root = MyModel()

def get_root(environ):
    return root
