# Internals

We plug together a large number of components to achieve multiple functionalities:

- Login to JupyterHub using OpenID Connect
- Provide access to external ressources from the user's notebook:
  - S3 (minio)
  - CIFS/SMB shares
  - git repositories (Gitlab, Github)

This document tries to go into some of the implementation details.

## Jupyterhub Login

Login to Jupyterhub using OAuth is achieved using
[oauthenticator](https://github.com/jupyterhub/oauthenticator).
We basically just configure and use its `GenericOAuthenticator` class from
`values.yaml` although via a subclass `KubeGenericOAuthenticator` which adds
logic required for the other use-cases.
There is no enhanced authorization, only the standard `allowed_users` and
`admin_users` settings of Jupyterhub.

## S3 access

Session credentials for access to minio S3 buckets are retrieved in method
[`pre_spawn_start()`](../files/jupyterhub/kubeoauth.py#L242) of our
`KubeGenericOAuthenticator` class.
This is delegated to a boto3 client and its method
`assume_role_with_web_identity()`.
The credentials returned are placed into a secret `jupyter-secrets-<username>`.
From there they're propagated to the user notebook as environment variables by
adding an `envFrom` definition to the container spec of the notebook container
about to be launched.
This needs to be done programatically because the name of the secret is
user-specific and needs to be constructed dynamically.

The same is done for the Dask worker containers.
The [`options_handler()`](../values.yaml#L180) callback of the Dask gateway
again provides a convenient way to inject these settings per-user.
It does not implement any user-selectable options currently but injects the
settings unconditionally.
There is no reason why they couldn't become optional though.

The injected `envFrom` definition in the container spec makes k8s pick up all
keys of the secret as respectively-named environment variables in the
container.
From there they'll automatically be picked up by most S3 clients, e.g. dask's
s3fs.

Refresh of these short-lived tokens is not currently implemented.
It should be achievable using the `refresh_user()` mechanism detailed below.

## SMB shares

Kerberos tickets for access to SMB shares are retrieved by
[gssproxy](https://github.com/gssapi/gssproxy) sidecar containers to the
Jupyter user notebook and Dask worker containers.
The basic container spec is done statically in `values.yaml` for both [Jupyter
user notebook](../values.yaml#L56) as well as [Dask
worker](../values.yaml#L250).

gssproxy only gets to see the effective UID of the requesting client and
derives the Kerberos principal by looking up the user name for that UID.
Since this is done in the gssproxy container, it can be set up to match our
requirements without disturbing Jupyter and Dask expectations (i.e. UID 1000
being user `jovyan` or `dask`).
To achieve this, the [entrypoint](../docker/gssproxy/entrypoint) of the gssproxy
container image processes an environment variable `GSSPROXY_CREATE_USERS`.
This can be a space-delimited list of `<username>=<uid` specifications.
The entrypoint will create each listed user before starting gssproxy.

We use this mechanism to create a user with the correct client UID (1000 for
both Jupyter notebook and Dask worker containers) but with the actual name of
the logged-in user.
The variable is again dynamically added to the sidecar container spec in
[`pre_spawn_start()`](../files/jupyterhub/kubeoauth.py#L261) of JupyterHub and
[`options_handler()`](../values.yaml#L190) of Dask gateway.
Further logic can be applied there if Kerberos principals do not match the
Oauth2/OpenID Connect user names (limited by the simple principal construction
logic implemented in gssproxy currently).

The UNIX domain socket of gssproxy is shared between sidecar and main
containers using an `emptyDir` volume [`gssproxy-sockets`](../values.yaml#L42).
Clients are told the path to the socket using environment variable
[`GSSPROXY_SOCKET`](../values.yaml#L35).

Since gssproxy is meant to service local clients on the same system, the socket
interface should be considered internal and not expected to be backward or
forward compatible.
It has been observed that different versions of Kerberos libraries in gssproxy
and client containers break functionality.
The gssproxy container should therefore match the client containers at least in
Kerberos library and gssproxy versions.
This is complicated by the fact that Conda has started adding Kerberos
libraries to their distribution which most of the time do not match the system
libraries in version and expect config files and plugins in Conda-specific
locations.
We have therefore opted to [recompile](../docker/jupyter/Dockerfile#L32) a
few Conda packages against the system libraries or without Kerberos support at
all to be able to uninstall the Conda krb5 packages.
As this is likely to escalate in effort over time, [first
attempts](../docker/jupyter/Dockerfile.conda-krb5) have been made to use the Conda
libraries instead.
To make this work reliablty, a gssproxy installation using the Conda libraries
will [likely need](../docker/jupyter/Dockerfile.conda-krb5#L38) to be added as
well.

## git repositories

Both
[Gitlab](https://gitlab.com/gitlab-org/gitlab/-/blob/master/vendor/jupyter/values.yaml)
and
[Github](https://github.blog/2012-09-21-easier-builds-and-deployments-using-git-over-https-and-oauth/)
accept OAuth tokens when accessing git repositories via HTTPS.

This functionality is distinct from and not to be confused with a.) configuring
Github or Gitlab to allow login using an external Identity Provider or b.) to
use Github or Gitlab as Identity Providers for e.g. login to JupyterHub.
While scenario b.) does as a side-effect provide JupyterHub with an access
token that can allow access to git repositories on that service, it also limits
login to JupyterHub to Github/Gitlab accounts and allow access only to
repositories hosted within that once instance.

Instead, here we're configuring Jupyter as a standard OAuth2 client to Gitlab
or Github in order to have the user authorize access and Jupyterhub be able to
retrieve access tokens from them.
This allows Jupyterhub, Gitlab and Github instances to use different identity
providers (which in the case of their cloud instances is a given).
Nothing prevents them from using the same Identity Provider though, enabling a
Single Sign-On experience for the user.
Also, in this setup JupyterHub can retrieve access tokens for multiple services
since it does so explicitly instead of relying on receiving one as a
side-effect during login.

It has not been tested yet whether [Identity
Brokering](https://www.keycloak.org/docs/latest/server_admin/#_identity_broker)
or [Federation](https://github.com/dexidp/dex) could solve this problem on the
infrastructure level without customization of JupyterHub.
Based on the documentation available, it is considered unlikely though.

The `KubeGenericOAuthenticator` class uses [the `callback_handler`
knob](../files/jupyterhub/kubeoauth.py#L42) to configure a custom callback
handler that changes the login HTTP request chain.
A custom class
[`ChainingOAuthCallbackHandler`](../files/jupyterhub/kubeoauth.py#L25) adds a
branching out of the default login flow just after the OpenID Connect
authentication to JupyterHub has finished and just before the user notebook
would be started.
This branching out is implemented as a redirect to either a Github or Gitlab
credential retrieval custom endpoint in JupyterHub.
This redirect is currently static but could be conditional on some selection
the user makes during login (the mechanism of which would need to be
implemented as well).

The place of implementation of the logic also means that access tokens are
retrieved during login for a static set of external services.
Therefore the list of services cannot be augmented on demand at runtime by the
user.

The respective credential retrieval endpoints are added by an overridden
[`get_handlers()`](../files/jupyterhub/kubeoauth.py#L108) method of
`KubeGenericOAuthenticator`.
These endpoints route requests to classes
[`GitlabCredsHandler`](../files/jupyterhub/gitlabcreds.py#L13) and
[`GithubCredsHandler`](../files/jupyterhub/githubcreds.py#L13), respectively.
They are based on the service-specific implementations of the JupyterHub login
logic in `oauthenticator` but omit the login authorization part since it is
irrelevant here.

When accessed, they construct a redirect to the Gitlab or Github OAuth2
authorize endpoints with all the parameters filled in to retrieve an
authorization code as per the [Authorization Code
Flow](https://oauth.net/2/grant-types/authorization-code/).
Where supported [PKCE](https://oauth.net/2/pkce/) is used.
When following that redirect, the browser may present the user with login and
authorisation pages of the respective service.

The callback URL given to the service and redirected back to after successful
authorisation is a second custom endpoint in JupyterHub.
These are serviced by classes
[`GitlabCredsCallbackHandler`](../files/jupyterhub/gitlabcreds.py#L52) and
[`GithubCredsCallbackHandler`](../files/jupyterhub/githubcreds.py#L54).
They use the authorization code provided in the callback parameters to retrieve
the actual access token from the service's token endpoint using a custom POST
request.
The access token is added to the user's auth state which is an existing
functionality of JupyterHub which needs to be [switched
on](../values.yaml#L125) to be available though.
This concludes the access token retrieval.

Whether the callback handler then redirects the user's browser to the original
notebook spawn endpoint or to another credential retrieval endpoint is
currently hard-coded in the classes.
There is no reason this couldn't be made more dynamic or adaptive.

The second part of the process is to transfer the tokens from the hub into the
user notebook.
This is done in hook
[`pre_spawn_start()`](../files/jupyterhub/kubeoauth.py#L313) based on the
existance of a Gitlab or Github access token in the user's auth state.
If either is the case, the user notebook pod spec is updated to add an
additional volume for a secret containing the tokens formatted as expected by
git in a `.git-credentials` file.
This secret is created using method
[`update_git_secret()`](../files/jupyterhub/kubeoauth.py#L176).

A [post-start lifecycle](../values.yaml#L75) hook for the notebook container
configures the credential store plugin and creates a symlink to the file to
preserve k8s atomic secret updates (see below).
git clients in the notebook using the git command or supporting the standard git
configuration mechanics will then be able to access repositories without any
authentication prompts.
One such client is [`jupyterlab-git` added](../docker/jupyter/Dockerfile#L61)
to our notebook image.

This functionality has been tested with Gitlab on k8s on-prem as well as the
Github cloud service.
It should work with the Gitlab cloud service as well as on-prem Github
Enterprise instances as well.
Jupyter needs to be registered as an OAuth2 client in both.
With on-prem instances this can be done for all users at once system-wide and
in the case of Gitlab even to such an extent that Jupyter is considered trusted
and no explicit authorization by the user is required for repo access.

As a comfort feature, the user's real name and email address are preconfigured
based on the [information retrieved](../files/jupyterhub/kubeoauth.py#L234)
from the OpenID connect userinfo endpoint during login by
`GenericOAuthenticator`.
They are passed to the notebook in environment variables `USER_NAME` and
`USER_EMAIL` from where they are picked up and configured globally for git by
the same post-start lifecycle hook as before.

Both Github and Gitlab issue non-expiring access tokens by default.
In the case of an on-prem installation this can be reconfigured, e.g. by
changing the configuration of the Doorkeeper ruby gem used by Gitlab to
implement OAuth2.
This is implemented in this setup to showcase use of refresh tokens by setting
[access token expire](../files/gitlab/doorkeeper.rb#L42) time to 20 minutes in
the configuration file.

JupyterHub provides a callback for refreshing short-lived user credentials in
the form of a [`refresh_user()`](../files/jupyterhub/kubeoauth.py#L118)
callback in authenticators.
It needs to be [enabled](../values.yaml#L127) together with auth state.
Our `KubeGenericOAuthenticator` uses it to refresh the access tokens for Gitlab or
Github if it received a refresh token together with the initial access token.
To this end it is stored in the user's auth state as well.
The hook calls method `update_git_secret()` to update the secret.
By employing k8s' atomic secret updates, this updates the `.git-credentials`
file in the user's notebook within a few seconds without restart or remount.
(Creating the k8s secret indirectly by refreshing the tokens once before spawn
using setting `refresh_before_spawn` turned out to not work reliably because it
happens independently of a possibly still running credential retrieval callback
chain.
This is why the secret is created explicitly in the pre spawn hook as well.)

Refresh tokens are kept exclusively within the users' auth state on the
JupyterHub instance and never exposed to the notebooks.
Only short-lived access tokens are exposed to the notebooks.
This mitigates leakage of access tokens from the `.git-credentials` file,
either accidentially or maliciously.
