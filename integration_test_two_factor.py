from keystoneclient.v3 import client
from keystoneclient import session
from keystoneclient.v3.contrib.two_factor import auth
import pyotp

url = 'http://127.0.0.1:5000/v3'

def fiwareclient(session=None, request=None):# TODO(garcianavalon) use this
    """Encapsulates all the logic for communicating with the modified keystone server.

    The IdM has its own admin account in the keystone server, and uses it to perform
    operations like create users, projects, etc. when there is no user with admin rights
    (for example, when user registration) to overcome the Keystone limitations.

    Also adds the methods to operate with the OAuth2.0 extension.
    """
    # TODO(garcianavalon) find a way to integrate this with the existng keystone api
    # TODO(garcianavalon)caching and efficiency with the client object.
    if not session:
        session = two_factor_session(user='idm_user', password='idm')
    keystone = client.Client(session=session)
    return keystone

def two_factor_session(user, password, verification_code=None, device_data=None, domain_id='default'):
    auth_object = auth.TwoFactor(auth_url=url,
                                 user_id=user,
                                 password=password,
                                 user_domain_id=domain_id,
                                 device_data=device_data,
                                 verification_code=verification_code)
    return session.Session(auth=auth_object)

def enable_two_factor(keystone, user):
    key = keystone.two_factor.keys.generate_new_key(user=user.id, security_question='Who?', security_answer='Me!')
    print "Created key for example_user: ", key.two_factor_key
    return key

def remember_device(keystone, **kwargs):
    device_data = keystone.two_factor.keys.remember_device(**kwargs)
    print "Remembering device for example_user: ", device_data.device_id
    return device_data

def authenticate(keystone, user, password, key=None, use_device_cookie=False, use_two_factor=True):
    if use_two_factor:
        if keystone.two_factor.keys.check_activated_two_factor(user_id=user.id):
            print "Two factor is enabled for example_user!"

            if use_device_cookie:
                device_data = remember_device(keystone=keystone, user_name=user.name, domain_id=user.domain_id)
                keystone2 = fiwareclient(session=two_factor_session(user=user.id,
                                                                    password=password,
                                                                    device_data={'device_id': device_data.device_id,
                                                                                 'device_token': device_data.device_token}))
                used_device_message = ' (remembering device)'
            else:
                code = pyotp.TOTP(key.two_factor_key).now()
                print code
                keystone2 = fiwareclient(session=two_factor_session(user=user.id,
                                                                    password=password,
                                                                    verification_code=code))
                used_device_message = ''
            try:
                keystone2.users.get(user.id)
                print "Auth with two factor{used_device} worked".format(used_device=used_device_message)
            except:
                print "Auth with two factor{used_device} didn't work".format(used_device=used_device_message)
        else:
            print "Two factor is disabled for exampleuser!"
    else:
        keystone3 = fiwareclient(session=two_factor_session(user=user.id,
                                                             password=password))
        try:
            keystone3.users.get(user.id)
            print "Auth without two factor worked"
        except:
            print "Auth without two factor didn't work"

def disable_two_factor(keystone, user):
    keystone.two_factor.keys.deactivate_two_factor(user=user.id)
    print "Disabling two factor..."

    if not keystone.two_factor.keys.check_activated_two_factor(user_id=user.id):
        print "Two factor is disabled for exampleuser!"

def main():
    keystone = fiwareclient()

    # Create example user
    project = keystone.projects.create(name="example_project", domain="default")
    role = keystone.roles.create(name="example_role")
    user = keystone.users.create(name="example_user", password="example_user", default_project=project)
    keystone.roles.grant(role=role, user=user, project=project)

    # Run tests
    key = enable_two_factor(keystone, user)
    authenticate(keystone, user, password="example_user", key=key, use_two_factor=True)
    authenticate(keystone, user, password="example_user", key=key, use_two_factor=True, use_device_cookie=True)
    disable_two_factor(keystone, user)
    authenticate(keystone, user, password="example_user", use_two_factor=False)

    # Delete example user
    keystone.projects.delete(project)
    keystone.roles.delete(role)
    keystone.users.delete(user)

if __name__ == "__main__":
    main()