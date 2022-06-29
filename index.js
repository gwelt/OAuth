var express = require('express');
var app = express();
var server = require('http').createServer(app);
var path = require('path');
var config = {}; try {config=require('./config.json')} catch(err){};
if ((!config)||(!config.web)||(!config.web.client_id)||(!config.web.client_secret)) {console.log('\n\n======================================================================================\nweb.client_id AND web.client_secret IN CONFIG-FILE (config.json) MUST HAVE A VALUE !!!\nsee https://developers.google.com/identity/protocols/oauth2/openid-connect?hl=en\nand https://console.cloud.google.com/\n======================================================================================\n\n');process.exit(0);}
var port = process.env.PORT || config.port || 3000;
const crypto = require("crypto");
const https = require('https');
server.listen(port, function () { console.log('\x1b[44m SERVER LISTENING ON PORT '+port+' \x1b[0m');});
process.on('SIGINT', function(){ if (config.SIGINT==undefined) {config.SIGINT=true; console.log('SIGINT'); process.exit(0);} });
process.on('SIGTERM', function(){ if (config.SIGTERM==undefined) {config.SIGTERM=true; console.log('SIGTERM'); process.exit(0);} });
var oauth_users=[];

/*
READ https://developers.google.com/identity/protocols/oauth2/openid-connect?hl=en
OBTAIN OAuth-CREDENDIALS via Google Cloud console (https://console.cloud.google.com/) and add "web"-part to config.json
>> "web":{"client_id":"example45709-b3gds9hcgv2kq5kaeoa97gkmeehres3h.apps.googleusercontent.com","project_id":"my-auth","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"EXAMPL-EFDEFSGHSgd8sdfg9VSFSDFEBFco","redirect_uris":["https://domain.com"]}
AUTHENTICATE THE USER
// 1. Create an anti-forgery state token
// 2. Send an authentication request to Google
// 3. Confirm the anti-forgery state token
// 4. Exchange code for access token and ID token
// 5. Obtain user information from the ID token
// 6. Authenticate the user
*/

app.use('(/oauth)?/:command?', function(req,res) {
	housekeeping();

	if (!req.params.command) {

		let u=find_user_by_cookie(req);

		// NEW USER
		if (!u && !req.query.state) {
			// start authentication-process by creating a new OAuthUser
			let user=new OAuthUser('https://'+req.get('host')+req.originalUrl.split("?").shift(),req.header('Referrer')); //req.protocol //req.header('Referrer') //req.body.referrer
			oauth_users.push(user);
			res.cookie('OAuthID',user.id);
			// 1. Create an anti-forgery state token
			user.anti_forgery_state_token=crypto.randomBytes(30).toString('hex');

			// 2. Send an authentication request to Google
			res.redirect('https://accounts.google.com/o/oauth2/auth?response_type=code&client_id='+config.web.client_id+'&scope=openid%20email&redirect_uri='+user.oauth_URI+'&state='+user.anti_forgery_state_token);
			res.end();
		}

		if (req.query.state) {			
			// 2a. Google will forward the user to this request: http://domain.com/oauth?state=6fdd22799abcd2ae39b69c1d3a5ac86238bae89db61d54d9a7cd32a462ba&code=4%2F0AX4XfWgfKNVrRdjzmXhrzwJJUvOQljez7HqvtM6gRGYTsGbLepfmdrtK823hU62OVdOjyA&scope=email+openid+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email&authuser=0&prompt=consent

			// 3. Confirm the anti-forgery state token
			let user=oauth_users.find(e=>e.anti_forgery_state_token==req.query.state);
			if (user) {

				// 4. Exchange code for access token and ID token
				let query='code='+req.query.code+'&client_id='+config.web.client_id+'&client_secret='+config.web.client_secret+'&redirect_uri='+encodeURI(user.oauth_URI)+'&grant_type=authorization_code';
				user.request({hostname:'oauth2.googleapis.com',path:'/token',method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'}},query,(r)=>{

					// 5. Obtain user information from the ID token
					// >> {"access_token": "ya29.A0ARrdaM8Lk_akOvQLRvcqUFe1aNBCnIGA7EcEujqQm2O08uS4cPLMlR6HJuLmkUvr1bsAKPlSNKM0ZDYqp8P3wmFoQqJfE65hNCtIIMSciI3nY_9jIELKpCwMMAi0EHFGoOBMb1C5HKotYs-UlbZIY76GkXDxYUNnWUtBVEFTQVRBU0ZRRl91NjFWaVdxeDJXVnBrTDA4SXFVa3Y1a0Mxdw0163", "expires_in": 3599, "scope": "openid https://www.googleapis.com/auth/userinfo.email", "token_type": "Bearer", "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjJiMDllNzQ0ZDU4Yzk5NTVkNGYyNDBiNmE5MmY3YjM3ZmVhZDJmZjgiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3NzMyOTUzNDU3MDktYjNsZWI5aGNndjJrcTVrYWVvYTk3Z2ttZWVocmVzM2guYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI3NzMyOTUzNDU3MDktYjNsZWI5aGNndjJrcTVrYWVvYTk3Z2ttZWVocmVzM2guYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDA3OTY3OTkzODgxNzYxOTc4NDQiLCJlbWFpbCI6InRvbS5nd2VsdEBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6InJPdnBWZ2RkUUNYem5hT0ZXbXBTc0EiLCJpYXQiOjE2NTY0MzE0ODYsImV4cCI6MTY1NjQzNTA4Nn0.bacHn7yxJNP0MSDrRb0yDqNE02T9ctT-Rmu255bPQdFVFOxqRwoOwDnz8LNN_5UvWe4i6-xShWJJxtaPq6jSih1KGB6W4EEq1oJtzJPKr7-rdmSOsRolEd2Q9WCUgB_sz7vOZASvsylruMw_mHie1VrutMQ-sZT9VeTEyaS0L_tt0rGMaPtVDJeDx2S6n0VEB-XKYizdcg0RKXOYNeqemcqCf_AjrubJRHRgLkMjBL_s-CvpYHOniUi9nBAN65MxMHkVWftA_eHd7pQKDMwHhhKe86T8wxp_PcKkD1n7zmqcSsASyZuh0daRs3I6JDiXs2FxpTPDgN2Ve5FnJ_eNrQ"}
					// r.id_token ...just the part between the two dots ('.') > base64-decode >> ...
				    let s=(/^[^\.]*\.([^\.]*)/i.exec(JSON.parse(r).id_token)); if (s) {
						let buff = Buffer.from(s[1],'base64');
						let payload=JSON.parse(buff.toString('utf-8'));

						// 6. Authenticate the user
						user.sub=payload.sub;
						user.email=payload.email;
						user.exp=payload.exp;
						user.anti_forgery_state_token=undefined;
				    }
				});

			}

			// in case the user does not have the cookie, send id
			if (!u) {if (user) {res.send(user.id);res.end()} else {res.sendStatus(404)}}
		}

		// EXISTING USER
		if (u) {
			if (u.redirect_URI) {res.redirect(u.redirect_URI); u.redirect_URI=undefined;} else {
				if (req.query.state) {res.redirect(u.oauth_URI)} else {
					let welcome='<b>Hello.</b> Thank you for using <a href='+u.oauth_URI+'>OAuth-service</a>.';
					if (u.email) {welcome='Hello <b>'+u.email+'</b>.'}
					welcome+='<br><a href='+u.oauth_URI+''+u.id+'>'+u.id+'</a> | <a href='+u.oauth_URI+'goodbye>say goodbye</a>';
					res.send(welcome);
				}
			};
			res.end();
		}

	} else {

		switch (req.params.command) {

			case 'users':
				// ADMINISTRATION / TEST ONLY !
				res.send(JSON.stringify(oauth_users));
				res.end();
				break;

			case 'goodbye':
				// logoff-request
				let current_user=find_user_by_cookie(req);
				if (current_user) {
					oauth_users=oauth_users.filter(e=>e.id!==current_user.id);
					if (current_user.redirect_URI) {res.redirect(current_user.redirect_URI)} else {
						res.send('Have a nice day. <a href='+current_user.oauth_URI+'>See you</a> soon.');
					}
				}
				res.end();			
				break;

			default:
				// query for a known id to check if user is authenticated
				let u=oauth_users.find(e=>e.id==req.params.command);
				if (u&&u.sub) {res.send(JSON.stringify(u))} else {res.sendStatus(404)}
				res.end();
				break;

		}

	}

});

function OAuthUser(oauth_URI,redirect_URI) {
	this.id=crypto.randomBytes(16).toString('hex');
	this.sub=undefined;
	this.email=undefined;
	this.exp=Math.floor(Date.now()/1000)+60;
	this.oauth_URI=oauth_URI;
	this.redirect_URI=redirect_URI;
	this.anti_forgery_state_token=undefined;
	return this;
}

OAuthUser.prototype.request = function (options,data,callback) {
	let req = https.request(options,res=>{let r='';res.on('data',d=>{r+=d});res.on('end',function(){callback(r)})});
	req.on('error', error => {callback('==ERROR== '+error)});
	req.write(data);
	req.end();
}

function housekeeping() {
	oauth_users=oauth_users.filter(e=>(Date.now()/1000)<e.exp);
}

function get_OAuthID_cookie_value(req) {
	let c=req.headers.cookie;
	if (c) {c=c.split('; ').filter(e=>e.startsWith('OAuthID='))[0]};
	if (c) {return c.split('=')[1]} else {return undefined}
}
function find_user_by_cookie(req) {
	let u=undefined;
	let c=get_OAuthID_cookie_value(req);
	if (c) {u=oauth_users.find(e=>e.id==c)}
	return u;
}
