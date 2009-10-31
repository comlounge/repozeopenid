from repoze.bfg.chameleon_zpt import render_template_to_response
from repoze.bfg.security import authenticated_userid

def my_view(context, request):
    return render_template_to_response('templates/mytemplate.pt',
                                       project = 'testapp',
                                       userid = authenticated_userid(request))
def login_form(context, request):
    return render_template_to_response('templates/login_form.pt',
                                      came_from = request.params.get('came_from',''))


def success(context, request):
    return render_template_to_response('templates/mytemplate.pt',
                                       project = 'whotest',
                                       userid = authenticated_userid(request))

def logout_success(context, request):
    return render_template_to_response('templates/logout_success.pt')

def where(context, request):
    return render_template_to_response('templates/where.pt')
