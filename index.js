const assert = require('assert');
const Provider = require('oidc-provider');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');

assert(process.env.PORT, 'process.env.PORT missing');
assert(process.env.MONGODB_URI, 'process.env.MONGODB_URI missing');

const jwks = require('./jwks.json');
const adapter = require('./mongodb'); // eslint-disable-line global-require
const Account = require('./account');

(async () => {
  const oidc = new Provider(`http://localhost`, {
    adapter: adapter,
    clients: [{
        client_id: 'foo',
        redirect_uris: ['https://example.com'],
        response_types: ['id_token'],
        grant_types: ['implicit'],
        token_endpoint_auth_method: 'none',
      }],
    jwks,
    findAccount: Account.findAccount,
    claims: {
      openid: ['sub'],
      email: ['email', 'email_verified'],
    },
    interactionUrl(ctx) {
      return `/interaction/${ctx.oidc.uid}`;
    },
    features: {
      // disable the packaged interactions
      devInteractions: { enabled: false },

      introspection: { enabled: true },
      revocation: { enabled: true },
    },
  });

  const expressApp = express();
  expressApp.set('view engine', 'ejs');
  expressApp.set('views', path.resolve(__dirname, 'views'));

  const parse = bodyParser.urlencoded({ extended: false });

  function setNoCache(req, res, next) {
    res.set('Pragma', 'no-cache');
    res.set('Cache-Control', 'no-cache, no-store');
    next();
  }

  expressApp.get('/interaction/:uid', setNoCache, async (req, res, next) => {
    try {
      const details = await oidc.interactionDetails(req);
      console.log('see what else is available to you for interaction views', details);
      const { uid, prompt, params } = details;

      const client = await oidc.Client.find(params.client_id);

      if (prompt.name === 'login') {
        return res.render('login', {
          client,
          uid,
          details: prompt.details,
          params,
          title: 'Sign-in',
          flash: undefined,
        });
      }

      return res.render('interaction', {
        client,
        uid,
        details: prompt.details,
        params,
        title: 'Authorize',
      });
    } catch (err) {
      return next(err);
    }
  });

  expressApp.post('/interaction/:uid/login', setNoCache, parse, async (req, res, next) => {
    try {
      const { uid, prompt, params } = await oidc.interactionDetails(req);
      const client = await oidc.Client.find(params.client_id);

      const accountId = await Account.authenticate(req.body.email, req.body.password);

      if (!accountId) {
        res.render('login', {
          client,
          uid,
          details: prompt.details,
          params: {
            ...params,
            login_hint: req.body.email,
          },
          title: 'Sign-in',
          flash: 'Invalid email or password.',
        });
        return;
      }

      const result = {
        login: {
          account: accountId,
        },
      };

      await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
      next(err);
    }
  });

  expressApp.post('/interaction/:uid/confirm', setNoCache, parse, async (req, res, next) => {
    try {
      const result = {
        consent: {
          // rejectedScopes: [], // < uncomment and add rejections here
          // rejectedClaims: [], // < uncomment and add rejections here
        },
      };
      await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
    } catch (err) {
      next(err);
    }
  });

  expressApp.get('/interaction/:uid/abort', setNoCache, async (req, res, next) => {
    try {
      const result = {
        error: 'access_denied',
        error_description: 'End-User aborted interaction',
      };
      await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
      next(err);
    }
  });

  // leave the rest of the requests to be handled by oidc-provider, there's a catch all 404 there
  expressApp.use(oidc.callback);
  expressApp.listen(process.env.PORT);
})();
