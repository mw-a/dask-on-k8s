import base64
import secrets
import hashlib

from tornado.auth import OAuth2Mixin
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
from oauthenticator.oauth2 import _deserialize_state


class GitlabCredsHandler(OAuth2Mixin, BaseHandler):
    @property
    def _OAUTH_AUTHORIZE_URL(self):
        return self.authenticator.gitlab_authorize_url

    async def get(self):
        redirect_uri= "%s://%s%s" % (self.request.protocol, self.request.host,
           url_path_join(self.hub.server.base_url, self.authenticator.gitlab_redirect_path))

        # PKCE bits stolen from https://github.com/RomeoDespres/pkce/blob/master/pkce/__init__.py
        code_verifier = secrets.token_urlsafe(96)
        hashed = hashlib.sha256(code_verifier.encode('ascii')).digest()
        encoded = base64.urlsafe_b64encode(hashed)
        code_challenge = encoded.decode('ascii')[:-1]

        # use auth state to transport code verifier to callback handler
        auth_state = await self.current_user.get_auth_state()
        auth_state['gitlab_code_verifier'] = code_verifier
        await self.current_user.save_auth_state(auth_state)

        # do not leak extra params intended for our IDP
        #extra_params = self.authenticator.extra_authorize_params.copy()
        self.log.info('Gitlab OAuth redirect: %r', redirect_uri)
        # but do copy state to propagate it to final redirect
        state = self.get_argument('state')
        extra_params = dict(
            state=state,
            code_challenge=code_challenge,
            code_challenge_method='S256',
        )
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.gitlab_client_id,
            scope=['read_repository', 'write_repository', 'api'],
            extra_params=extra_params,
            response_type='code',
        )


class GitlabCredsCallbackHandler(BaseHandler):
    async def get(self):
        # stolen from GitlabOAuthenticator but without authentication part
        code = self.get_argument("code")
        redirect_uri= "%s://%s%s" % (self.request.protocol, self.request.host,
           url_path_join(self.hub.server.base_url, self.authenticator.gitlab_redirect_path))

        auth_state = await self.current_user.get_auth_state()
        code_verifier = auth_state.get('gitlab_code_verifier')

        params = dict(
            client_id=self.authenticator.gitlab_client_id,
            client_secret=self.authenticator.gitlab_client_secret,
            code=code,
            code_verifier=code_verifier,
            grant_type="authorization_code",
            redirect_uri=redirect_uri,
        )

        url = url_concat(self.authenticator.gitlab_token_uri, params)

        req = HTTPRequest(
            url,
            method="POST",
            headers={"Accept": "application/json"},
            validate_cert=True,
            body='',  # Body is required for a POST...
        )

        resp_json = await self.authenticator.fetch(req, label="getting access token")

        # remember access and refresh tokens in auth state
        auth_state = await self.current_user.get_auth_state()
        auth_state['gitlab_access_token'] = resp_json.get('access_token')
        auth_state['gitlab_refresh_token'] = resp_json.get('refresh_token')
        await self.current_user.save_auth_state(auth_state)

        state = self.get_argument('state')

        # drop user into notebook with url retrieved from state
        #next_url = _deserialize_state(state).get('next_url')
        #if not next_url:
        #    next_url = url_path_join(self.hub.server.base_url, 'home')

        # or chain in the next external resource provider credential
        # retrieval, propagating state
        params = dict(state=state)
        next_url = url_concat(url_path_join(self.hub.server.base_url,
            self.authenticator.github_creds_path), params)

        self.redirect(next_url)
