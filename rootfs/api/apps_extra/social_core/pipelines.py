from api.serializers import UserSerializer


def update_or_create(backend, user, response, *args, **kwargs):
    user, created = UserSerializer.update_or_create(response)
    return {'is_new': created, 'user': user}
