from tornado.wsgi import WSGIContainer


from api.wsgi import application as handler


application = WSGIContainer(handler)
