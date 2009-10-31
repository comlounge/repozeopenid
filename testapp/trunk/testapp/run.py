from repoze.bfg.router import make_app

def app(global_config, **kw):
    # paster app config callback
    from testapp.models import get_root
    import testapp
    return make_app(get_root, testapp, options=kw)

if __name__ == '__main__':
    from paste import httpserver
    httpserver.serve(app(None), host='0.0.0.0', port='6543')
    
