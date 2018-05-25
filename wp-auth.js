var crypto = require('crypto'),
    phpjs = require('./serialize');

function sanitizeValue(value) {
    switch (typeof value) {
        case 'boolean':
        case 'object':
            return phpjs.serialize(value).replace(/(\'|\\)/g, '\\$1');
        case 'number':
            return Number.toString.call(value);
        case 'string':
            try {
                // If it is a serialized string, serialize it again so it comes back out of the database the same way.
                return phpjs.serialize(phpjs.serialize(phpjs.unserialize(value))).replace(/(\'|\\)/g, '\\$1');
            } catch (ex) {
                return value.replace(/(\'|\\)/g, '\\$1');
            }
        default:
            throw new Error('Invalid data type: ' + typeof value);
    }
}

function WP_Auth(wpurl, logged_in_key, logged_in_salt,
                 mysql_connection,
                 wp_table_prefix) {
    var md5 = crypto.createHash('md5');
    md5.update(wpurl);
    this.cookiename = 'wordpress_logged_in_' + md5.digest('hex');
    this.salt = logged_in_key + logged_in_salt;

    this.db = mysql_connection;
	/*this.db = require('../mysql-native').createTCPClient(mysql_host, mysql_port);
	 this.db.auth(mysql_db, mysql_user, mysql_pass);*/

    this.table_prefix = wp_table_prefix;

    this.known_hashes = {};
    this.known_hashes_timeout = {};
    this.meta_cache = {};
    this.meta_cache_timeout = {};

    // Default cache time: 5 minutes
    this.timeout = 300000;
}

WP_Auth.prototype.checkAuth = function(req) {
    var self = this,
        data = null,
	allCookieNames = [];
    if (req.headers.cookie)
        req.headers.cookie.split(';').forEach(function(cookie) {
	    allCookieNames.push(cookie.split('=')[0].trim());
            if (cookie.split('=')[0].trim() == self.cookiename)
                data = cookie.split('=')[1].trim().split('%7C');
        });
    else
        return new Invalid_Auth("no cookie");
	
    console.log('allCookieNames', allCookieNames);
    console.log('data', data);
    console.log('cookieName', self.cookiename);

    if (!data)
        return new Invalid_Auth("no data in cookie " + self.cookiename);

    if (parseInt(data[1]) < new Date / 1000)
        return new Invalid_Auth("expired cookie");

    return new Valid_Auth(data, this);
};

exports.create = function(wpurl, logged_in_key, logged_in_salt,
                          mysql_connection,
                          wp_table_prefix) {
    return new WP_Auth(wpurl, logged_in_key, logged_in_salt,
        mysql_connection,
        wp_table_prefix);
};

function Invalid_Auth(err) {
    this.err = err;
}

Invalid_Auth.prototype.on = function(key, callback) {
    if (key != 'auth')
        return this;
    var self = this;
    process.nextTick(function() {
        callback.call(self, false, 0, self.err);
    });
    return this;
};

function Valid_Auth(data, auth) {
    var self = this,
        user_login = data[0],
        expiration = data[1],
        token = data[2],
        hash = data[3];

    // For email address used as login
    user_login = user_login.replace('%40', '@');

    if (user_login in auth.known_hashes_timeout && auth.known_hashes_timeout[user_login] < +new Date) {
        delete auth.known_hashes[user_login];
        delete auth.known_hashes_timeout[user_login];
    }

    function parse(pass_frag, id) {
        var hmac1 = crypto.createHmac('md5', auth.salt);
        var key = user_login + '|' + pass_frag + '|' + expiration + '|' + token;
        hmac1.update(key);
        var hkey = hmac1.digest('hex');
        var hmac2 = crypto.createHmac('sha256', hkey);
        hmac2.update(user_login + '|' + expiration + '|' + token);
        var cookieHash = hmac2.digest('hex');
        if (hash == cookieHash) {
            self.emit('auth', true, id, user_login);
        } else {
            self.emit('auth', false, 0, "invalid hash");
        }
    }

    if (user_login in auth.known_hashes) {
        return process.nextTick(function() {
            parse(auth.known_hashes[user_login].frag, auth.known_hashes[user_login].id);
        });
    }


    var found = false;

    auth.db.getConnection(function(err, connection){
	    if ( err ) { console.log('auth.db.getConnection', err); connection.release(); return; }
        connection.query({
            sql : 'select ID, user_pass from ' + auth.table_prefix + 'users where user_login = \'' + user_login.replace(/(\'|\\)/g, '\\$1') + '\'',
            timeout : 1000
        }, function(err, rows, fields){
		if ( err ){ console.log('auth.db.query error', err); connection.release(); return; }  
		
            console.log('rows', rows);
            var data = typeof rows[0] == 'undefined' ? false : rows[0];

            if ( err || ! data ){ //FAILURE
                auth.known_hashes[user_login] = {
                    frag: '__fail__',
                    id: 0
                };
                auth.known_hashes_timeout[user_login] = +new Date + auth.timeout;
            } else { //SUCCESS
                auth.known_hashes[user_login] = {
                    frag: data.user_pass.substr(8, 4),
                    id: data.ID
                };
                auth.known_hashes_timeout[user_login] = +new Date + auth.timeout;
            }

            parse(auth.known_hashes[user_login].frag, auth.known_hashes[user_login].id);

            connection.release();
        });
    });

	/*auth.db.query()
	 .on('row', function(data) {
	 found = true;
	 auth.known_hashes[user_login] = {
	 frag: data.user_pass.substr(8, 4),
	 id: data.ID
	 };
	 auth.known_hashes_timeout[user_login] = +new Date + auth.timeout;
	 })
	 .on('end', function() {
	 if (!found) {
	 auth.known_hashes[user_login] = {
	 frag: '__fail__',
	 id: 0
	 };
	 auth.known_hashes_timeout[user_login] = +new Date + auth.timeout;
	 }
	 parse(auth.known_hashes[user_login].frag, auth.known_hashes[user_login].id);
	 });*/

}

require('util').inherits(Valid_Auth, require('events').EventEmitter);
