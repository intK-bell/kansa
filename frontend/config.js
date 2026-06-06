(function () {
  const prod = {
    apiBase: 'https://api.ph4k.aokigk.com',
    photoBucket: 'kansa-backend-photobucket-ufurvgtp4oqi',
    cognitoRegion: 'ap-northeast-1',
    cognitoDomain: 'photohub4kansa',
    cognitoClientId: 'nlpccd2h79jr93rejmiv35eci',
    cognitoRedirectUri: window.location.origin,
  };

  const dev = {
    apiBase: 'https://dev-api.ph4k.aokigk.com',
    photoBucket: 'kansa-backend-dev-photobucket-j8ixrzh8g0u0',
    cognitoRegion: 'ap-northeast-1',
    cognitoDomain: 'photohub4kansa-dev',
    cognitoClientId: '5qqtnnoh2eqmm01esn9cstl448',
    cognitoRedirectUri: window.location.origin,
  };

  const host = String(window.location.hostname || '').toLowerCase();
  const isLocal = host === 'localhost' || host === '127.0.0.1';
  const isDevHost = host === 'dev.d3vej31wy18srw.amplifyapp.com';
  window.KANSA_CONFIG = isLocal || isDevHost ? dev : prod;
})();
