import boto3
import base64
import uuid

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest
from jupyterhub.utils import url_path_join
from oauthenticator.generic import GenericOAuthenticator
from oauthenticator.oauth2 import OAuthCallbackHandler, _serialize_state
from kubernetes.client.models import V1Secret, V1ObjectMeta
from kubernetes.client.rest import ApiException
from kubernetes.client import V1DeleteOptions
from traitlets import Bool, Unicode, default, observe


# jupyter hub auth flow:
# /oauth_login -> IDP -> /oauth_callback -> /hub -> /hub/spawn -> ...
#
# we add:
# /oauth_login -> IDP -> /oauth_callback
# -> /gitlab_creds -> Gitlab Service (+ potentially another IDP) -> /gitlab_creds_callback
# [-> /github_creds -> Github Service (+ potentially another IDP) -> /github_creds_callback
# -> /hub -> /hub/spawn -> ...

class ChainingOauthCallbackHandler(OAuthCallbackHandler):
    def get_next_url(self, user=None):
        """ Redirect to a different URI to acquire additional creds for the user """
        # put original authenticator next url into new state to
        # preserve it across additional roundtrips to different
        # services
        state = dict(
            state_id=uuid.uuid4().hex,
            next_url=super().get_next_url(user),
        )
        params = dict(state=_serialize_state(state))
        return url_concat(url_path_join(self.hub.server.base_url,
            self.authenticator.gitlab_creds_path), params)
        #return url_concat(url_path_join(self.hub.server.base_url,
        #    self.authenticator.github_creds_path, params)

class KubeGenericOAuthenticator(GenericOAuthenticator):
    callback_handler = ChainingOauthCallbackHandler

    minio_enabled = Bool(False, config=True)
    minio_endpoint_url = Unicode(config=True)

    gitlab_url_scheme = Unicode("https", config=True)
    gitlab_host = Unicode("gitlab.com", config=True)
    gitlab_authorize_path = Unicode("/oauth/authorize", config=True)
    gitlab_authorize_url = Unicode(config=True)

    @default("gitlab_authorize_url")
    def _default_gitlab_authorize_url(self):
        return "%s://%s%s" % (self.gitlab_url_scheme, self.gitlab_host,
           self.gitlab_authorize_path)

    @observe('gitlab_url_scheme', 'gitlab_url_scheme', 'gitlab_authorize_path')
    def _gitlab_authorize_url_components_changed(self, change):
        self.gitlab_authorize_url = self._default_gitlab_authorize_url()

    gitlab_token_path = Unicode("/oauth/token", config=True)
    gitlab_token_uri = Unicode(config=True)
    @default("gitlab_token_uri")
    def _default_gitlab_token_uri(self):
        return "%s://%s%s" % (self.gitlab_url_scheme, self.gitlab_host,
           self.gitlab_token_path)

    @observe('gitlab_url_scheme', 'gitlab_url_scheme', 'gitlab_token_path')
    def _gitlab_token_uri_components_changed(self, change):
        self.gitlab_token_uri = self._default_gitlab_token_uri()

    gitlab_client_id = Unicode(config=True)
    gitlab_client_secret = Unicode(config=True)
    gitlab_creds_path = Unicode("/gitlab_creds", config=True)
    gitlab_redirect_path = Unicode("/gitlab_creds_callback", config=True)

    github_host = Unicode("github.com", config=True)
    github_url_scheme = Unicode("https", config=True)
    github_authorize_path = Unicode("/login/oauth/authorize", config=True)
    github_authorize_url = Unicode(config=True)

    @default("github_authorize_url")
    def _default_github_authorize_url(self):
        return "%s://%s%s" % (self.github_url_scheme, self.github_host,
            self.github_authorize_path)

    @observe('github_url_scheme', 'github_url_scheme', 'github_authorize_path')
    def _github_authorize_url_components_changed(self, change):
        self.github_authorize_url = self._default_github_authorize_url()

    github_token_path = Unicode("/login/oauth/access_token", config=True)
    github_token_uri = Unicode(config=True)

    @default("github_token_uri")
    def _default_github_token_uri(self):
        return "%s://%s%s" % (self.github_url_scheme, self.github_host,
            self.github_token_path)

    @observe('github_url_scheme', 'github_url_scheme', 'github_token_path')
    def _github_token_uri_components_changed(self, change):
        self.github_token_uri = self._default_github_token_uri()

    github_client_id = Unicode(config=True)
    github_client_secret = Unicode(config=True)
    github_creds_path = Unicode("/github_creds", config=True)
    github_redirect_path = Unicode("/github_creds_callback", config=True)

    def get_handlers(self, app):
        handlers = super().get_handlers(app)
        handlers.extend((
          (r'%s' % self.gitlab_creds_path, GitlabCredsHandler),
          (r'%s' % self.gitlab_redirect_path, GitlabCredsCallbackHandler),
          (r'%s' % self.github_creds_path, GithubCredsHandler),
          (r'%s' % self.github_redirect_path, GithubCredsCallbackHandler),
        ))
        return handlers

    async def refresh_user(self, user, handler=None):
        self.log.info('refresh user: %s', user.name)
        auth_state = await user.get_auth_state()
        gitlab_access_token = auth_state.get('gitlab_access_token')
        gitlab_refresh_token = auth_state.get('gitlab_refresh_token')
        if gitlab_access_token and gitlab_refresh_token:
            params = dict(
                grant_type="refresh_token",
                refresh_token=gitlab_refresh_token,
                client_id=self.gitlab_client_id,
                client_secret=self.gitlab_client_secret,
            )

            url = url_concat(self.gitlab_token_uri, params)

            req = HTTPRequest(
                url,
                method="POST",
                headers={"Accept": "application/json"},
                validate_cert=True,
                body='',  # Body is required for a POST...
            )

            resp_json = await self.fetch(req, label="getting refreshed access token")
            auth_state['gitlab_access_token'] = resp_json.get('access_token')
            # gitlab uses doorkeeper and doorkeeper does refresh
            # token rotation by default. So we get a new refresh
            # token with each access token, invalidating the old
            # refresh token. Nice!
            auth_state['gitlab_refresh_token'] = resp_json.get('refresh_token')

        github_access_token = auth_state.get('github_access_token')
        github_refresh_token = auth_state.get('github_refresh_token')
        if github_access_token and github_refresh_token:
            params = dict(
                grant_type="refresh_token",
                refresh_token=github_refresh_token,
                client_id=self.github_client_id,
                client_secret=self.github_client_secret,
            )

            url = url_concat(self.github_token_uri, params)

            req = HTTPRequest(
                url,
                method="POST",
                headers={"Accept": "application/json"},
                validate_cert=True,
                body='',  # Body is required for a POST...
            )

            resp_json = await self.fetch(req, label="getting refreshed access token")
            auth_state['github_access_token'] = resp_json.get('access_token')
            auth_state['github_refresh_token'] = resp_json.get('refresh_token')

        await self.update_git_secret(user, auth_state)
        return {'auth_state': auth_state}

    async def update_git_secret(self, user, auth_state):
        ''' update the git secret '''
        secret_name = "jupyter-git-secrets-%s" % user.escaped_name

        self.log.info("Updating git secret: %s", secret_name)

        git_credentials = ""
        gitlab_access_token = auth_state.get('gitlab_access_token')
        if gitlab_access_token:
            self.log.debug("Adding Gitlab secret")
            gitlab_url = "%s://oauth2:%s@%s" % (self.gitlab_url_scheme,
                gitlab_access_token, self.gitlab_host)
            git_credentials += "%s\n" % gitlab_url

        github_access_token = auth_state.get('github_access_token')
        if github_access_token:
            self.log.debug("Adding Github secret")
            # OAuth App
            github_url = "%s://%s:x-oauth-basic@%s" % (self.github_url_scheme,
                github_access_token, self.github_host)
            # Github App
            #github_url = "https://x-access-token:%s@%s" % (github_access_token, github_host)
            git_credentials += "%s\n" % github_url

        secret = V1Secret()
        secret.kind = "Secret"
        secret.api_version = "v1"
        secret.metadata = V1ObjectMeta()
        secret.metadata.name = secret_name
        secret.data = {
            'git-credentials': base64.encodebytes(git_credentials.encode('ascii')).decode('ascii'),
        }

        for server_name in user.spawners:
            spawner = user.spawners[server_name]
            try:
                await spawner.asynchronize(
                    spawner.api.replace_namespaced_secret,
                    secret_name,
                    spawner.namespace,
                    secret)
            except ApiException as e:
                if e.status != 404:
                    raise

                await spawner.asynchronize(
                    spawner.api.create_namespaced_secret,
                    spawner.namespace,
                    secret)

            # we only have one secret for all notebooks for now
            break

    async def pre_spawn_start(self, user, spawner):
        self.log.info('Pre spawn start : %s', user.name)
        auth_state = await user.get_auth_state()
        access_token = auth_state['access_token']

        real_name = auth_state.get('oauth_user', {}).get('name')
        if real_name:
            spawner.environment['USER_REAL_NAME'] = real_name

        email = auth_state.get('oauth_user', {}).get('email')
        if email:
            spawner.environment['USER_EMAIL'] = email

        if self.minio_enabled:
            sts_client = boto3.client(
                'sts',
                region_name='us-east-1',
                use_ssl=False,
                endpoint_url=self.minio_endpoint_url,
            )

            response = sts_client.assume_role_with_web_identity(
                RoleArn='arn:aws:iam::123456789012:user/svc-internal-api',
                RoleSessionName='test',
                WebIdentityToken=access_token,
                DurationSeconds=3600
            )

            access_key = response['Credentials']['AccessKeyId']
            secret_key = response['Credentials']['SecretAccessKey']
            session_token = response['Credentials']['SessionToken']

        for c in spawner.extra_containers:
            if c['name'] != "gssproxy":
                continue

            if 'env' not in c:
                c['env'] = []

            c['env'].append({
                'name': 'GSSPROXY_CREATE_USERS',
                'value': '%s=1000' % user.escaped_name})

        secret_name = "jupyter-secrets-%s" % user.escaped_name

        secret = V1Secret()
        secret.kind = "Secret"
        secret.api_version = "v1"
        secret.metadata = V1ObjectMeta()
        secret.metadata.name = secret_name
        #secret.metadata.annotations = (annotations or {}).copy()
        #secret.metadata.labels = (labels or {}).copy()
        #secret.metadata.owner_references = owner_references

        secret.data = {}
        if self.minio_enabled:
            secret.data['AWS_ACCESS_KEY_ID'] = base64.encodebytes(access_key.encode('ascii')).decode('ascii')
            secret.data['AWS_SECRET_ACCESS_KEY'] = base64.encodebytes(secret_key.encode('ascii')).decode('ascii')
            secret.data['AWS_SESSION_TOKEN'] = base64.encodebytes(session_token.encode('ascii')).decode('ascii')

        try:
            await spawner.asynchronize(
                spawner.api.delete_namespaced_secret,
                name=secret_name,
                namespace=spawner.namespace,
                body=V1DeleteOptions())
        except ApiException as e:
            if e.status != 404:
                raise

        await spawner.asynchronize(
            spawner.api.create_namespaced_secret,
            spawner.namespace,
            secret)

        if 'envFrom' not in spawner.extra_container_config:
            spawner.extra_container_config['envFrom'] = []

        spawner.extra_container_config['envFrom'].append({
                'secretRef': {
                    'name': secret_name,
                }
            })

        gitlab_access_token = auth_state.get('gitlab_access_token')
        github_access_token = auth_state.get('github_access_token')
        if gitlab_access_token or github_access_token:
            secret_name = "jupyter-git-secrets-%s" % user.escaped_name

            # user secret refresh and user interaction with external
            # resources for sign-in may race each other and leave the
            # secrets incomplete at first if we do not forcibly
            # update them here
            await self.update_git_secret(user, auth_state)

            spawner.volumes.append({
                'name': 'git-credentials',
                'secret': {
                    'secretName': secret_name,
                }})

            spawner.volume_mounts.append({
                'name': 'git-credentials',
                'mountPath': '/home/jovyan/.config/jupyter/git-credentials',
                })

    async def post_spawn_stop(self, user, spawner):
        try:
            await spawner.asynchronize(
                spawner.api.delete_namespaced_secret,
                name="jupyter-secrets-%s" % user.escaped_name,
                namespace=spawner.namespace,
                body=V1DeleteOptions())
        except ApiException as e:
            if e.status != 404:
                raise

        try:
            await spawner.asynchronize(
                spawner.api.delete_namespaced_secret,
                name="jupyter-git-secrets-%s" % user.escaped_name,
                namespace=spawner.namespace,
                body=V1DeleteOptions())
        except ApiException as e:
            if e.status != 404:
                raise
