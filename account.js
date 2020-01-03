const { MongoClient } = require('mongodb'); // eslint-disable-line import/no-unresolved
const assert = require('assert');

let DB;

(async () => {
  const connection = await MongoClient.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
  });
  DB = connection.db(connection.s.options.dbName);
  await DB.collection('users').insertMany([
    {
      _id: '23121d3c-84df-44ac-b458-3d63a9a05497',
      email: 'foo@example.com',
      email_verified: true,
    },
    {
      _id: 'c2ac2b4a-2262-4e2f-847a-a40dd3c4dcd5',
      email: 'bar@example.com',
      email_verified: false,
    },
  ])
})();

class Account {
  // This interface is required by oidc-provider
  static async findAccount(ctx, _id) {
    // This would ideally be just a check whether the account is still in your storage
    const account = await DB.collection('users').findOne({ _id });
    if (!account) {
      return undefined;
    }

    return {
      accountId: _id,
      // and this claims() method would actually query to retrieve the account claims
      async claims() {
        return {
          sub: _id,
          email: account.email,
          email_verified: account.email_verified,
        };
      },
    };
  }

  // This can be anything you need to authenticate a user
  static async authenticate(email, password) {
    try {
      assert(password, 'password must be provided');
      assert(email, 'email must be provided');
      const lowercased = String(email).toLowerCase();
      const account = await DB.collection('users').findOne({ 'email': lowercased });
      assert(account, 'invalid credentials provided');

      return account._id;
    } catch (err) {
      return undefined;
    }
  }
}

module.exports = Account;
