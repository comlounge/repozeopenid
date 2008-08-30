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

_DEFAULT_FORM = """
<html>
<head>
  <title>Log In</title>
</head>
<body>
  <div>
     <b>Log In</b>
  </div>
  <br/>
  <form method="POST" action="?__do_login=true">
    <input type="hidden" name="__do_login" value="1" />
    <table border="0">
    <tr>
      <td>Your OpenID:</td>
      <td><input type="text" name="openid"></input></td>
    </tr>
    <tr>
      <td></td>
      <td><input type="submit" name="submit" value="Log In"/></td>
    </tr>
    </table>
  </form>
  <pre>
  </pre>
</body>
</html>
"""


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
                    came_from_field = ''):
        print "init", store
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
        
        

    def get_consumer(self,environ):
        session = environ[self.session_name]        
        return consumer.Consumer(session,self.store)
        
    def redirect_to_logged_in(self, environ):
        """redirect to came_from or standard page"""
        request = Request(environ)
        came_from = request.params.get(self.came_from_field,'')
        if came_from!='':
            url = came_from
        else:
            url = self.logged_in_url
        print "doing redirect to", url
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
        
        # now check if we maybe are already identified, what joy would that be!
        session = environ[self.session_name]
        identity = session.get('repoze.whoplugins.openid.openid', {})
        if identity.has_key('repoze.who.userid'):
            # check if we are still in the login path. redirect if necessary
            if request.path == self.login_handler_path:
                self.redirect_to_logged_in(environ)
            return identity

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
                    identity['repoze.who.userid']= display_identifier
                    del environ['repoze.whoplugins.openid.openid']
                    
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
        session = environ[self.session_name]        
        session['repoze.whoplugins.openid.openid'] = identity
        print session
        session.save()

    # IIdentifier
    def forget(self, environ, identity):
        """forget about the authentication again"""
        session = environ[self.session_name]
        if session.has_key('repoze.whoplugins.openid.openid'):
            del session['repoze.whoplugins.openid.openid']
            session.save()

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
        session = environ[self.session_name]

        try:
            openid_request = self.get_consumer(environ).begin(openid_url)
            session.save()
        except consumer.DiscoveryFailure, exc:
            # TODO: Put this into self.error_field
            environ['repoze.whoplugins.openid.error'] = 'Error in discovery: %s' %exc[0]
            return None
        else:
            if openid_request is None:
                # TODO: Put this into self.error_field
                environ['repoze.whoplugins.openid.error'] = 'No OpenID services found for %s' %openid_url
                return None
            else:
                # TODO: Can we use the MD plugin to add sreg and AX if necessary?
                # TODO: Who has to do PAPE?
                #if use_sreg:
                    #self.requestRegistrationData(request)

                #if use_pape:
                    #self.requestPAPEDetails(request)

                return_to = request.path_url # use the same
                trust_root = request.application_url
                
                # What do we have to do if this is not True?
                if openid_request.shouldSendRedirect():
                    redirect_url = openid_request.redirectURL(
                                    trust_root, return_to, immediate=False)
                                    # TODO: check what immediate means again
                    res = Response()
                    res.status = 302
                    res.location = redirect_url
                    return res

                else:
                    print "ELSE?!?"
                    # TODO: what is this and how do we handle this
                    # real TODO: read openid lib docs
                    #form_html = request.htmlMarkup(
                    #trust_root, return_to,
                    #form_tag_attrs={'id':'openid_message'},
                    #immediate=immediate)
                    #
                    #self.wfile.write(form_html)
                    return None
                
    # IAuthenticator
    def authenticate(self, environ, identity):
        """dummy authenticator"""
        if identity.has_key("repoze.whoplugins.openid.openid"):
                return identity.get('repoze.whoplugins.openid.openid')


    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))

def make_plugin(store='mem',
                openid_field = "openid",
                session_name = None,
                login_handler_path = None,
                logout_handler_path = None,
                login_form_url = None,
                error_field = 'error',
                logged_in_url = None,
                logged_out_url = None,
                came_from_field = None,
                store_file_path=''):
    if store not in (u'mem',u'file'):
        raise ValueError("store needs to be 'sql' or 'file'")
    if login_form_url is None:
        raise ValueError("login_form_url needs to be given")
    if login_handler_path is None:
        raise ValueError("login_handler_path needs to be given")
    if logout_handler_path is None:
        raise ValueError("logout_handler_path needs to be given")
    if session_name is None:
        raise ValueError("session_name needs to be given")
    if logged_in_url is None:
        raise ValueError("logged_in_url needs to be given")
    if logged_out_url is None:
        raise ValueError("logged_out_url needs to be given")

    plugin = OpenIdIdentificationPlugin(store, 
        openid_field = openid_field,
        error_field = error_field,
        session_name = session_name,
        login_form_url = login_form_url,
        login_handler_path = login_handler_path,
        logout_handler_path = logout_handler_path,
        store_file_path = store_file_path,
        logged_in_url = logged_in_url,
        logged_out_url = logged_out_url,
        came_from_field = came_from_field
        
        )
    return plugin

