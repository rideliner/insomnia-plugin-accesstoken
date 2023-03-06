async function getTokens(context, authenticationRequest, useIdentityToken) {
  const token = await context.util.models.oAuth2Token.getByRequestId(authenticationRequest._id);
  const accessToken = ( useIdentityToken ? (token || {}).identityToken : (token || {}).accessToken ) || '';
  return {token, accessToken};
}

module.exports = {
  name: 'token',
  displayName: 'Access Token',
  description: "reference access token from other requests",
  args: [
    {
      displayName: 'Request',
      type: 'model',
      model: 'Request',
    },
    {
      displayName: 'Disable Auto Prefix',
      type: 'boolean',
      help: 'If this is disabled, your token will lack the prefix as specified on the source request.',
      defaultValue: false,
    },
    {
      displayName: 'Disable Expired Token Check',
      type: 'boolean',
      help: 'If this is disabled, you will not receive a notice when the token expires.',
      defaultValue: false,
    },
    {
      displayName: 'Disable Missing Token Check',
      type: 'boolean',
      help: 'If this is disabled, you will not receive a notice when the token is missing.',
      defaultValue: false,
    },
    {
      displayName: 'Auto-refresh Token',
      type: 'boolean',
      help: 'If this is enabled, trigger the request to get the token.',
      defaultValue: true
    },
    {
      displayName: 'Use Identity Token',
      type: 'boolean',
      help: 'If this is enabled, use the identityToken instead of accessToken.',
      defaultValue: false,
    },
  ],

  async run(context,
    oauthRequestId,
    disableAutoPrefix,
    disableExpiredTokenCheck,
    disableMissingTokenCheck,
    autoRefreshToken,
    useIdentityToken,
  ) {
    const { meta } = context;

    if (!meta.requestId || !meta.workspaceId) {
      return null;
    }

    if (!oauthRequestId) {
      throw new Error('No request specified');
    }

    const authenticationRequest = await context.util.models.request.getById(oauthRequestId);
    const prefix = disableAutoPrefix ? '' : ((authenticationRequest || {}).authentication || {}).tokenPrefix || '';

    var {token, accessToken} = await getTokens(context, authenticationRequest, useIdentityToken);

    if (context.renderPurpose == null) {
      return `${prefix} ${accessToken || "<token-pending>"}`.trim();
    }

    if (autoRefreshToken && (!accessToken || token.expiresAt < new Date())) {
      await context.network.sendRequest(authenticationRequest);
      var {token, accessToken} = await getTokens(context, authenticationRequest, useIdentityToken);
    }

    if (!accessToken) {
      if (!disableMissingTokenCheck)
        await context.app.alert("Access Token", "The token is missing");

      return '';
    }
    else if (token.expiresAt < new Date()) {
      if (!disableExpiredTokenCheck)
        await context.app.alert("Access Token", "The token has expired");

      return '';
    }

    return `${prefix} ${accessToken}`.trim();
  }
};
