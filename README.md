TotoClient-JS
=============
Use `toto.js` to call your Toto based webservice.

Call `var toto = new Toto(url)` to get an instance of the toto client that points to your `url`, then use `toto.request(method, args, successCallback(response), errorCallback(error))` to call
your service. `method` is the string name of the method to call, `args` is the javascript object that will be JSON serialized and sent as the method arguments.
`successCallback` and `errorCallback` are both optional.

Use `toto.createAccount(userID, password, args, successCallback, errorCallback)` to create a new account. `args` is a dictionary that contains any additional parameters that your
account.create method takes, or `null` if not needed.

`toto.authenticate(userID, password, successCallback, errorCallback)` can be used to log in to an existing account. Both `toto.authenticate` and `toto.createAccount` will result in a logged
in session, and all future calls to `toto.request` will be authenticated.

Toto uses localStorage to store the User ID and Session ID for each domain, so it is possible to use multiple Toto services simultaneously.

TotoClient-JS uses [jsSHA][jsSHA] for HMAC.

[jsSHA]:http://jssha.sourceforge.net/
