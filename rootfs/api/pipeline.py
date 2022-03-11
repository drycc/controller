from api.serializers import UserSerializer


def update_or_create(backend, user, response, *args, **kwargs):
    user, created = UserSerializer.update_or_create(response)

    if not created:
        return {'is_new': False}

    return {
        'is_new': True,
        'user': user
    }


def load_extra_data(backend, details, response, uid, user, *args, **kwargs):
    social = kwargs.get('social') or \
             backend.strategy.storage.user.get_social_auth(backend.name, uid)
    if social:
        extra_data = backend.extra_data(user, uid, response, details,
                                        *args, **kwargs)
        social.set_extra_data(extra_data)
