import cgi
import urlparse
import cgitb
import sys

from repoze.who.interfaces import IChallenger
from repoze.who.interfaces import IIdentifier

import openid
from openid.store import memstore
from openid.store import filestore
from openid.consumer import consumer
from openid.oidutil import appendArgs
from openid.cryptutil import randomString
from openid.fetchers import setDefaultFetcher, Urllib2Fetcher
from openid.extensions import pape, sreg


class OpenIdChallengerPlugin(object):

    def __init__(self, store, openidname, store_filename=''):
	print "init", store
	if store==u"mem":
	    self.store = memstore.MemoryStore()
	elif store==u"file":
	    raise NotImplemented
	self.openidname = openidname

    # IIdentifier
    def identify(self, environ):
	print "identifying"
        identity = {}
	if environ.has_key(self.openidname):
	    identity['repoze.whoplugins.openid.openid'] = environ[self.openidname]

	print "ret",identity
        return identity

    # IIdentifier
    def forget(self, environ, identity):
	print "forget"
        pass
    
    # IIdentifier
    def remember(self, environ, identity):
	print "forget"
        pass
        pass


    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))

def make_plugin(store='mem',
		store_filename='',
                openidname='__openid'):
    if store not in (u'mem',u'file'):
        raise ValueError("store needs to be 'mem' or 'file'")
    plugin = OpenIdIdentificationPlugin(store, openidname,store_filename=store_filename)
    return plugin

