def update_user(backend, user, response, *args, **kwargs):
    user.username = response.get('username')
    user.email = response.get('email')
    user.first_name = response.get('first_name')
    user.last_name = response.get('last_name')
    user.is_superuser = response.get('is_superuser')
    user.is_staff = response.get('is_staff')
    user.is_active = response.get('is_active')
    user.save()


def load_extra_data(backend, details, response, uid, user, *args, **kwargs):
    social = kwargs.get('social') or \
             backend.strategy.storage.user.get_social_auth(backend.name, uid)
    if social:
        extra_data = backend.extra_data(user, uid, response, details,
                                        *args, **kwargs)
        social.set_extra_data(extra_data)
