import cgi
import urlparse
import cgitb
import sys
from zope.interface import implements

from repoze.who.interfaces import IChallenger
from repoze.who.interfaces import IIdentifier
from repoze.who.interfaces import IAuthenticator

from webob import Request, Response

import openid
from openid.store import memstore
from openid.store import filestore
from openid.consumer import consumer
from openid.oidutil import appendArgs
from openid.cryptutil import randomString
from openid.fetchers import setDefaultFetcher, Urllib2Fetcher
from openid.extensions import pape, sreg



class OpenIdIdentificationPlugin(object):


    implements(IChallenger, IIdentifier, IAuthenticator)

    def __init__(self, store, openid_field, 
                    error_field = '',
                    store_file_path='',
                    session_name = '',
                    login_handler_path = '',
                    logout_handler_path = '',
                    login_form_url = '',
                    logged_in_url = '',
                    logged_out_url = '',
                    came_from_field = '',
                    rememberer_name = ''):

        self.rememberer_name = rememberer_name
        self.login_handler_path = login_handler_path
        self.logout_handler_path = logout_handler_path
        self.login_form_url = login_form_url
        self.session_name = session_name
        self.error_field = error_field
        self.came_from_field = came_from_field
        self.logged_out_url = logged_out_url
        self.logged_in_url = logged_in_url
        
        # set up the store
        if store==u"file":
            self.store = filestore.FileOpenIDStore(store_file_path)
        elif store==u"sql":
            raise NotImplemented
        self.openid_field = openid_field
        
    def _get_rememberer(self, environ):
        rememberer = environ['repoze.who.plugins'][self.rememberer_name]
        return rememberer

    def get_consumer(self,environ):
        #session = environ[self.session_name]        
        return consumer.Consumer({},self.store)
        
    def redirect_to_logged_in(self, environ):
        """redirect to came_from or standard page if login was successful"""
        request = Request(environ)
        came_from = request.params.get(self.came_from_field,'')
        if came_from!='':
            url = came_from
        else:
            url = self.logged_in_url
        res = Response()
        res.status = 302
        res.location = url
        environ['repoze.who.application'] = res    

    # IIdentifier
    def identify(self, environ):
        request = Request(environ)

        # first test for logout as we then don't need the rest
        if request.path == self.logout_handler_path:
            self.forget(environ,{})
            res = Response()
            res.status = 302
            res.location = self.logged_out_url
            environ['repoze.who.application'] = res
            return {}

        identity = {}

        # we are not identified yet, check if we might have an openid request
        if request.path == self.login_handler_path:
            # we put this into the environ so the challenger knows that we
            # provided it and replaces the response
            identity['repoze.whoplugins.openid.openid'] = environ['repoze.whoplugins.openid.openid'] = request.params.get(self.openid_field)

            # start challenge
            mode=request.params.get("openid.mode", None)
            if mode=="id_res":
                oidconsumer = self.get_consumer(environ)
                info = oidconsumer.complete(request.params, request.url)

                if info.status == consumer.SUCCESS:
                    display_identifier = info.getDisplayIdentifier()
                    
                    # remove this so that the challenger is not triggered again
                    del environ['repoze.whoplugins.openid.openid']
                    
                    # store the id for the authenticator
                    identity['repoze.who.plugins.openid.userid'] = display_identifier

                    # now redirect to came_from or the success page
                    self.redirect_to_logged_in(environ)
                    return identity
                    
                # TODO: Do we have to check for more failures and such?
                # 
            elif mode=="cancel":
                # cancel is a negative assertion in the OpenID protocol,
                # which means the user did not authorize correctly.
                environ['repoze.whoplugins.openid.error'] = 'OpenID authentication failed.'
                pass
        return identity

    # IIdentifier
    def remember(self, environ, identity):
        """remember the openid in the session we have anyway"""
        rememberer = self._get_rememberer(environ)
        return rememberer.remember(environ, identity)

    # IIdentifier
    def forget(self, environ, identity):
        """forget about the authentication again"""
        print "forgetting", identity
        rememberer = self._get_rememberer(environ)
        return rememberer.forget(environ, identity)

    # IChallenge
    def challenge(self, environ, status, app_headers, forget_headers):
        """do the challenge bit by redirecting"""
        request = Request(environ)
        
        # maybe there is no openid in the request to check, then go back to login_form
        if not request.params.has_key(self.openid_field):
            # redirect to login_form
            res = Response()
            res.status = 302
            res.location = self.login_form_url+"?%s=%s" %(self.came_from_field, request.url)
            return res
       
        openid_url = request.params[self.openid_field]

        try:
            openid_request = self.get_consumer(environ).begin(openid_url)
        except consumer.DiscoveryFailure, exc:
            environ[self.error_field] = 'Error in discovery: %s' %exc[0]
            return None
        except KeyError, exc:
            environ[self.error_field] = 'Error in discovery: %s' %exc[0]
            # TODO: when does that happen, why does plone.openid use "pass" here?
            return None
            
        if openid_request is None:
            environ[self.error_field] = 'No OpenID services found for %s' %openid_url
            return None
            
        # TODO: Can we use the MD plugin to add sreg and AX if necessary?
        # TODO: Who has to do PAPE?
        #if use_sreg:
            #self.requestRegistrationData(request)

        #if use_pape:
            #self.requestPAPEDetails(request)

        return_to = request.path_url # we return to this URL here
        trust_root = request.application_url
        print return_to
        
        # TODO: usually you should check openid_request.shouldSendRedirect()
        # but this might say you have to use a form redirect and I don't get why
        # so we do the same as plone.openid and ignore it.
        redirect_url = openid_request.redirectURL(trust_root, return_to) 
        # # , immediate=False)
        res = Response()
        res.status = 302
        res.location = redirect_url
        return res
                
    # IAuthenticator
    def authenticate(self, environ, identity):
        """dummy authenticator"""
        print "authing", identity
        if identity.has_key("repoze.who.plugins.openid.userid"):
                print "authed"
                return identity.get('repoze.who.plugins.openid.userid')


    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))

