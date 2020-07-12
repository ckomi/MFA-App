var User = require('../models/user');
var jwt = require('jsonwebtoken');
var secret = 'some secret';
var nodemailer = require('nodemailer');
var sgTransport = require('nodemailer-sendgrid-transport');
var address = require('address');
var Speakeasy = require('speakeasy');
var cookieParser = require('cookie-parser');
const oneDayToSeconds = 1680000 * 60 * 60;

module.exports = function(router) {
    var client = nodemailer.createTransport(sgTransport({
        auth: {
            api_key: 'your api key for SEND GRID'
        }
    }));

    const getAppCookies = (req) => {
        try {
            const rawCookies = req.headers.cookie.split('; ');
            const parsedCookies = {};
            rawCookies.forEach(rawCookie => {
                const parsedCookie = rawCookie.split('=');
                parsedCookies[parsedCookie[0]] = parsedCookie[1];
            });
            return parsedCookies["checkLogin"].replace(/%3A/g, ":");
        } catch (err) {
            return '0';
        }
    };

    router.post('/users', function(req, res) {
        var user = new User();
        user.username = req.body.username;
        user.password = req.body.password;
        user.email = req.body.email;
        user.phone = req.body.phone;
        user.name = req.body.name;
        user.temporarytoken = jwt.sign({ username: user.username, email: user.email }, secret, { expiresIn: '24h' });
        user.userIP = (req.headers['x-forwarded-for'] || req.connection.remoteAddress || '').split(',')[0].trim();
        if (req.body.username == null || req.body.username == '' || req.body.password == null || req.body.password == '' || req.body.email == null || req.body.email == '' || req.body.phone == null || req.body.phone == '' || req.body.name == null || req.body.name == '') {
            res.json({ success: false, message: 'Ensure username, email, and password were provided' });
        } else {
            user.save(function(err) {
                if (err) {
                    console.log("Frs err", err);
                    if (err.errors !== null) {
                        console.log("err error", err.errors);
                        if (err.errors.name) {
                            res.json({ success: false, message: err.errors.name.message });
                        } else if (err.errors.email) {
                            res.json({ success: false, message: err.errors.email.message });
                        } else if (err.errors.username) {
                            res.json({ success: false, message: err.errors.username.message });
                        } else if (err.errors.phone) {
                            res.json({ success: false, message: err.errors.phone.message });
                        } else if (err.errors.password) {
                            res.json({ success: false, message: err.errors.password.message });
                        } else {
                            res.json({ success: false, message: err });
                        }
                    } else if (err) {
                        if (err.code == 11000) {
                            if (err.errmsg[61] == "u") {
                                res.json({ success: false, message: 'That username is already taken' });
                            } else if (err.errmsg[61] == "p") {
                                res.json({ success: false, message: 'That phone is in use' });
                            } else if (err.errmsg[61] == "e") {
                                res.json({ success: false, message: 'That e-mail is already taken' });
                            }
                        } else {
                            res.json({ success: false, message: err });
                        }
                    }
                } else {
                    var email = {
                        from: 'MFA App, multifactorauthentification@gmail.com',
                        to: [user.email],
                        subject: 'Activation Link',
                        text: 'Hello ' + user.name + ', thank you for registering at Multi-Factor Authentication. Please click on the following button to complete your activation: http://localhost:8080/activate/' + user.temporarytoken,
                        html: 'Hello<strong> ' + user.name + '</strong>,<br><br>Thank you for registering at Multi-Factor Authentication. Please click on the button below to complete your activation:<br><br><button style="background-color: #00aeff; border: none; border-radius: 5px; padding:10px;"><a style="color: #FFF; font-weight: bolder; text-decoration: none;" href="http://localhost:8080/activate/' + user.temporarytoken + '">Activate Now</a></button>'
                    };
                    client.sendMail(email, function(err, info) {
                        if (err) {
                            console.log(err);
                        } else {
                            console.log(info);
                            console.log(user.email);
                        }
                    });
                    res.cookie('checkLogin', user.userIP, {
                        maxAge: oneDayToSeconds,
                        httpOnly: true
                    });
                    res.json({ success: true, message: 'Account registered! Please check your e-mail for activation link.' });
                }
            });
        }
    });

    router.post('/checkusername', function(req, res) {
        User.findOne({ username: req.body.username }).select('username').exec(function(err, user) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                if (user) {
                    res.json({ success: false, message: 'That username is already taken' });
                } else {
                    res.json({ success: true, message: 'Valid username' });
                }
            }
        });
    });

    router.post('/checkemail', function(req, res) {
        User.findOne({ email: req.body.email }).select('email').exec(function(err, user) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                if (user) {
                    res.json({ success: false, message: 'That e-mail is already taken' });
                } else {
                    res.json({ success: true, message: 'Valid e-mail' });
                }
            }
        });
    });

    router.post('/checkphone', function(req, res) {
        User.findOne({ phone: req.body.phone }).select('phone').exec(function(err, user) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                if (user) {
                    res.json({ success: false, message: 'That phone is already taken' });
                } else {
                    res.json({ success: true, message: 'Valid phone' });
                }
            }
        });
    });

    router.post('/authenticate', function(req, res) {
        const getUserIp = getAppCookies(req);
        var loginUser = (req.body.username).toLowerCase();
        User.findOne({ username: loginUser }).select('name email username phone password active userIP').exec(function(err, user) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                if (!user) {
                    res.json({ success: false, message: 'Username not found' });
                } else if (user) {
                    if (!req.body.password) {
                        res.json({ success: false, message: 'No password provided' });
                    } else {
                        var validPassword = user.comparePassword(req.body.password);
                        if (!validPassword) {
                            res.json({ success: false, message: 'Could not authenticate password' });
                        } else if (!user.active) {
                            res.json({ success: false, message: 'Account is not yet activated. Please check your e-mail for activation link.', expired: true });
                        } else {
                            if (getUserIp === user.userIP) {
                                var shortFullName = user.name.split(' ');
                                var justName = shortFullName[0];
                                var token = jwt.sign({ justName: justName, name: user.name, username: user.username, email: user.email, phone: user.phone }, secret, { expiresIn: '24h' });
                                res.json({ success: true, secondLogin: false, message: 'Success logged in', token: token });
                            } else {
                                var totpSecret = Speakeasy.generateSecret({ length: 20 }).base32
                                var totpToken = {
                                    "sixDigitToken": Speakeasy.totp({
                                        totpSecret: totpSecret,
                                        encoding: "base32"
                                    }),
                                    "remaining": new Date().getTime() + 250000
                                }
                                User.findOneAndUpdate({ username: req.body.username }, { topSecondLogin: { totpToken: totpToken.sixDigitToken, tokenRemaining: totpToken.remaining } }, { upsert: false }, function(err, doc) {
                                    if (err) { console.log("error " + err) }
                                });
                                var email = {
                                    from: 'MFA App, multifactorauthentification@gmail.com',
                                    to: [user.email],
                                    subject: '6-digit Number',
                                    text: 'Hello ' + user.name + ', We recently detected new device when someone try to login' + totpToken.sixDigitToken,
                                    html: 'Hello<strong> ' + user.name + '</strong>,<br><br>We recently detected new device when someone try to login, If that is you, use 6-digit code below <br><br>Code: <a style="color: #ff1100; font-weight: bolder; text-decoration: none;">' + totpToken.sixDigitToken + '</a>'
                                };
                                client.sendMail(email, function(err, info) {
                                    if (err) {
                                        console.log(err);
                                    } else {
                                        console.log(info);
                                        console.log(user.email);
                                    }
                                });
                                res.json({ username: user.username, email: user.email, success: false, secondLogin: true, totpToken: totpToken, totpSecret: totpSecret, message: 'New device detected, check your email inbox!' });
                            }
                        }
                    }
                }
            }
        });
    });
    router.post('/secondauthenticate', async function(req, res) {
        var getIp = (req.headers['x-forwarded-for'] || req.connection.remoteAddress || '').split(',')[0].trim();
        if (!req.body.username) {
            res.json({ message: 'You must fill in the first step, try again!' });
        } else {
            User.findOne({ username: req.body.username }, function(err, user) {
                var shortFullName = user.name.split(' ');
                var justName = shortFullName[0];
                var timeNow = new Date().getTime();
                if (timeNow < user.topSecondLogin.tokenRemaining) {
                    if (req.body.totpPin == user.topSecondLogin.totpToken) {
                        var token = jwt.sign({ justName: justName, name: user.name, username: user.username, email: user.email, phone: user.phone }, secret, { expiresIn: '24h' });
                        User.findOneAndUpdate({ username: req.body.username }, { userMac: userMac }, { upsert: false }, function(err, doc) {
                            if (err) { console.log("error " + err) }
                        });
                        res.cookie('checkLogin', getIp, {
                            maxAge: oneDayToSeconds,
                            httpOnly: true
                        });
                        res.json({ totpAuth: true, message: 'Success veryfing new device', token: token });
                        var email = {
                            from: 'MFA App, multifactorauthentification@gmail.com',
                            to: [user.email],
                            subject: 'New Device Authenticated',
                            text: 'Hello ' + user.name + ',  New device was authenticated, have a nice day!',
                            html: 'Hello<strong> ' + user.name + '</strong>,<br><br>New device was authenticated, have a nice day!</a>'
                        };
                        client.sendMail(email, function(err, info) {
                            if (err) {
                                console.log(err);
                            } else {
                                console.log(info);
                                console.log(user.email);
                            }
                        });
                    } else {
                        res.json({ totpAuth: false, message: 'Error authenticate pin, try again' });
                    }
                } else {
                    res.json({ totpAuth: false, message: 'Token time has expired' });
                }
            });
        }
    });

    router.put('/activate/:token', function(req, res) {
        User.findOne({ temporarytoken: req.params.token }, function(err, user) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                var token = req.params.token;
                jwt.verify(token, secret, function(err, decoded) {
                    if (err) {
                        res.json({ success: false, message: 'Activation link has expired.' });
                    } else if (!user) {
                        res.json({ success: false, message: 'Activation link has expired.' });
                    } else {
                        user.temporarytoken = false;
                        user.active = true;
                        user.save(function(err) {
                            if (err) {
                                console.log(err);
                            } else {
                                var email = {
                                    from: 'MFA App, multifactorauthentification@gmail.com',
                                    to: user.email,
                                    subject: 'Account Activated',
                                    text: 'Hello ' + user.name + ', Your account has been successfully activated!',
                                    html: 'Hello<strong> ' + user.name + '</strong>,<br><br>Your account has been successfully activated!'
                                };
                                client.sendMail(email, function(err, info) {
                                    if (err) console.log(err);
                                });
                                res.json({ success: true, message: 'Account activated!' });
                            }
                        });
                    }
                });
            }
        });
    });

    router.post('/resend', function(req, res) {
        User.findOne({ username: req.body.username }).select('username password active').exec(function(err, user) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                if (!user) {
                    res.json({ success: false, message: 'Could not authenticate user' });
                } else if (user) {
                    if (req.body.password) {
                        var validPassword = user.comparePassword(req.body.password);
                        if (!validPassword) {
                            res.json({ success: false, message: 'Could not authenticate password' });
                        } else if (user.active) {
                            res.json({ success: false, message: 'Account is already activated.' });
                        } else {
                            res.json({ success: true, user: user });
                        }
                    } else {
                        res.json({ success: false, message: 'No password provided' });
                    }
                }
            }
        });
    });

    router.put('/resend', function(req, res) {
        User.findOne({ username: req.body.username }).select('username name email temporarytoken').exec(function(err, user) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                user.temporarytoken = jwt.sign({ username: user.username, email: user.email }, secret, { expiresIn: '24h' });
                user.save(function(err) {
                    if (err) {
                        console.log(err);
                    } else {
                        var email = {
                            from: 'MFA App, multifactorauthentification@gmail.com',
                            to: user.email,
                            subject: 'Activation Link',
                            text: 'Hello ' + user.name + ', You recently requested a new account activation link. Please click on the following button to complete your activation: http://localhost:8080/activate/' + user.temporarytoken,
                            html: 'Hello<strong> ' + user.name + '</strong>,<br><br>You recently requested a new account activation link. Please click on the button below to complete your activation:<br><br><button style="background-color: #00aeff; border: none; border-radius: 5px; padding:10px;"><a style="color: #FFF; font-weight: bolder; text-decoration: none;" href="http://localhost:8080/activate/' + user.temporarytoken + '">Activate Now</a></button>'
                        };
                        client.sendMail(email, function(err, info) {
                            if (err) console.log(err);
                        });
                        res.json({ success: true, message: 'Activation link has been sent to ' + user.email + '!' });
                    }
                });
            }
        });
    });

    router.get('/resetusername/:email', function(req, res) {
        User.findOne({ email: req.params.email }).select('email name username').exec(function(err, user) {
            if (err) {
                res.json({ success: false, message: err });
            } else {
                if (!user) {
                    res.json({ success: false, message: 'E-mail was not found' });
                } else {
                    var email = {
                        from: 'MFA App, multifactorauthentification@gmail.com',
                        to: user.email,
                        subject: 'Forgoten USERNAME',
                        text: 'Hello ' + user.name + ', You recently requested your username. Please save it in your files: ' + user.username,
                        html: 'Hello<strong> ' + user.name + '</strong>,<br><br>You recently requested your username. Please save it in your files: ' + user.username
                    };
                    client.sendMail(email, function(err, info) {
                        if (err) {
                            console.log(err);
                        } else {
                            console.log(info);
                        }
                    });
                    res.json({ success: true, message: 'Username has been sent to e-mail! ' });
                }
            }
        });
    });

    router.put('/resetpassword', function(req, res) {
        User.findOne({ username: req.body.username }).select('username active email resettoken name').exec(function(err, user) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                if (!user) {
                    res.json({ success: false, message: 'Username was not found' });
                } else if (!user.active) {
                    res.json({ success: false, message: 'Account has not yet been activated' });
                } else {
                    user.resettoken = jwt.sign({ username: user.username, email: user.email }, secret, { expiresIn: '24h' });
                    user.save(function(err) {
                        if (err) {
                            res.json({ success: false, message: err });
                        } else {
                            var email = {
                                from: 'MFA App, multifactorauthentification@gmail.com',
                                to: user.email,
                                subject: 'Reset PASSWORD',
                                text: 'Hello ' + user.name + ', You recently request a password reset link. Please click on the button below to reset your password:<br><br><a href="http://localhost:8080/reset/' + user.resettoken,
                                html: 'Hello<strong> ' + user.name + '</strong>,<br><br>You recently request a password reset link. Please click on the button below to reset your password:<br><br><button style="background-color: #00aeff; border: none; border-radius: 5px; padding:10px;"><a style="color: #FFF; font-weight: bolder; text-decoration: none;" href="http://localhost:8080/reset/' + user.resettoken + '">Reset Password</a></button>'
                            };
                            client.sendMail(email, function(err, info) {
                                if (err) {
                                    console.log(err);
                                } else {
                                    console.log(info);
                                    console.log('sent to: ' + user.email);
                                }
                            });
                            res.json({ success: true, message: 'Please check your e-mail for password reset link' });
                        }
                    });
                }
            }
        });
    });

    router.get('/resetpassword/:token', function(req, res) {
        User.findOne({ resettoken: req.params.token }).select().exec(function(err, user) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                var token = req.params.token;
                jwt.verify(token, secret, function(err, decoded) {
                    console.log(" If Err jwt.ver", token);
                    if (err) {
                        console.log(" If Err jwt.ver", );
                        res.json({ success: false, message: 'Password link has expired' });
                    } else {
                        if (!user) {
                            res.json({ success: false, message: 'Password link has expired' });
                        } else {
                            res.json({ success: true, user: user });
                        }
                    }
                });
            }
        });
    });

    router.put('/savepassword', function(req, res) {
        User.findOne({ username: req.body.username }).select('username email name password resettoken').exec(function(err, user) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                if (req.body.password === null || req.body.password === '') {
                    res.json({ success: false, message: 'Password not provided' });
                } else {
                    user.password = req.body.password;
                    user.resettoken = false;
                    user.save(function(err) {
                        if (err) {
                            res.json({ success: false, message: err });
                        } else {
                            var email = {
                                from: 'MFA App, multifactorauthentification@gmail.com',
                                to: user.email,
                                subject: 'Password Recently Reset',
                                text: 'Hello ' + user.name + ', This e-mail is to notify you that your password was recently reset.',
                                html: 'Hello<strong> ' + user.name + '</strong>,<br><br>This e-mail is to notify you that your password was recently reset.'
                            };
                            client.sendMail(email, function(err, info) {
                                if (err) console.log(err);
                            });
                            res.json({ success: true, message: 'Password has been reset!' });
                        }
                    });
                }
            }
        });
    });

    router.use(function(req, res, next) {
        var token = req.body.token || req.body.query || req.headers['x-access-token'];

        if (token) {
            jwt.verify(token, secret, function(err, decoded) {
                if (err) {
                    res.json({ success: false, message: 'Invalid Token' });
                } else {
                    req.decoded = decoded;
                    next();
                }
            });
        } else {
            res.json({ success: false, message: 'Token is not provided' });
        }
    });

    router.post('/me', function(req, res) {
        res.send(req.decoded);
    });

    router.get('/renewToken/:username', function(req, res) {
        User.findOne({ username: req.params.username }).select('username email').exec(function(err, user) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                if (!user) {
                    res.json({ success: false, message: 'No user was found' });
                } else {
                    var newToken = jwt.sign({ username: user.username, email: user.email }, secret, { expiresIn: '24h' });
                    res.json({ success: true, token: newToken });
                }
            }
        });
    });

    router.get('/permission', function(req, res) {
        User.findOne({ username: req.decoded.username }, function(err, user) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                if (!user) {
                    res.json({ success: false, message: 'No user was found' });
                } else {
                    res.json({ success: true, permission: user.permission });
                }
            }
        });
    });

    router.get('/management', function(req, res) {
        User.find({}, function(err, users) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                User.findOne({ username: req.decoded.username }, function(err, mainUser) {
                    if (err) {
                        var email = {
                            from: 'MFA App Error, multifactorauthentification@gmail.com',
                            to: 'multifactorauthentification@gmail.com',
                            subject: 'Error Logged',
                            text: 'The following error has been reported in the MFA Application: ' + err,
                            html: 'The following error has been reported in the MFA Application:<br><br>' + err
                        };
                        client.sendMail(email, function(err, info) {
                            if (err) {
                                console.log(err);
                            } else {
                                console.log(info);
                                console.log(user.email);
                            }
                        });
                        res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
                    } else {
                        if (!mainUser) {
                            res.json({ success: false, message: 'No user found' });
                        } else {
                            if (mainUser.permission === 'admin' || mainUser.permission === 'moderator') {
                                if (!users) {
                                    res.json({ success: false, message: 'Users not found' });
                                } else {
                                    res.json({ success: true, users: users, permission: mainUser.permission });
                                }
                            } else {
                                res.json({ success: false, message: 'Insufficient Permissions' });
                            }
                        }
                    }
                });
            }
        });
    });

    router.delete('/management/:username', function(req, res) {
        var deletedUser = req.params.username;
        User.findOne({ username: req.decoded.username }, function(err, mainUser) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                if (!mainUser) {
                    res.json({ success: false, message: 'No user found' });
                } else {
                    if (mainUser.permission !== 'admin') {
                        res.json({ success: false, message: 'Insufficient Permissions' });
                    } else {
                        User.findOneAndRemove({ username: deletedUser }, function(err, user) {
                            if (err) {
                                var email = {
                                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                                    to: 'multifactorauthentification@gmail.com',
                                    subject: 'Error Logged',
                                    text: 'The following error has been reported in the MFA Application: ' + err,
                                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                                };
                                client.sendMail(email, function(err, info) {
                                    if (err) {
                                        console.log(err);
                                    } else {
                                        console.log(info);
                                        console.log(user.email);
                                    }
                                });
                                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
                            } else {
                                res.json({ success: true });
                            }
                        });
                    }
                }
            }
        });
    });

    router.get('/edit/:id', function(req, res) {
        var editUser = req.params.id;
        User.findOne({ username: req.decoded.username }, function(err, mainUser) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                if (!mainUser) {
                    res.json({ success: false, message: 'No user found' });
                } else {
                    if (mainUser.permission === 'admin' || mainUser.permission === 'moderator') {
                        User.findOne({ _id: editUser }, function(err, user) {
                            if (err) {
                                var email = {
                                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                                    to: 'multifactorauthentification@gmail.com',
                                    subject: 'Error Logged',
                                    text: 'The following error has been reported in the MFA Application: ' + err,
                                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                                };
                                client.sendMail(email, function(err, info) {
                                    if (err) {
                                        console.log(err);
                                    } else {
                                        console.log(info);
                                        console.log(user.email);
                                    }
                                });
                                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
                            } else {
                                if (!user) {
                                    res.json({ success: false, message: 'No user found' });
                                } else {
                                    res.json({ success: true, user: user });
                                }
                            }
                        });
                    } else {
                        res.json({ success: false, message: 'Insufficient Permission' });
                    }
                }
            }
        });
    });

    router.put('/edit', function(req, res) {
        var editUser = req.body._id;
        if (req.body.name) var newName = req.body.name;
        if (req.body.username) var newUsername = req.body.username;
        if (req.body.email) var newEmail = req.body.email;
        if (req.body.phone) var newPhone = req.body.phone;
        if (req.body.permission) var newPermission = req.body.permission;
        User.findOne({ username: req.decoded.username }, function(err, mainUser) {
            if (err) {
                var email = {
                    from: 'MFA App Error, multifactorauthentification@gmail.com',
                    to: 'multifactorauthentification@gmail.com',
                    subject: 'Error Logged',
                    text: 'The following error has been reported in the MFA Application: ' + err,
                    html: 'The following error has been reported in the MFA Application:<br><br>' + err
                };
                client.sendMail(email, function(err, info) {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log(info);
                        console.log(user.email);
                    }
                });
                res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
            } else {
                if (!mainUser) {
                    res.json({ success: false, message: "no user found" });
                } else {
                    if (newName) {
                        if (mainUser.permission === 'admin' || mainUser.permission === 'moderator') {
                            User.findOne({ _id: editUser }, function(err, user) {
                                if (err) {
                                    var email = {
                                        from: 'MFA App Error, multifactorauthentification@gmail.com',
                                        to: 'multifactorauthentification@gmail.com',
                                        subject: 'Error Logged',
                                        text: 'The following error has been reported in the MFA Application: ' + err,
                                        html: 'The following error has been reported in the MFA Application:<br><br>' + err
                                    };
                                    client.sendMail(email, function(err, info) {
                                        if (err) {
                                            console.log(err);
                                        } else {
                                            console.log(info);
                                            console.log(user.email);
                                        }
                                    });
                                    res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
                                } else {
                                    if (!user) {
                                        res.json({ success: false, message: 'No user found' });
                                    } else {
                                        user.name = newName;
                                        user.save(function(err) {
                                            if (err) {
                                                console.log(err);
                                            } else {
                                                res.json({ success: true, message: 'Name has been updated!' });
                                            }
                                        });
                                    }
                                }
                            });
                        } else {
                            res.json({ success: false, message: 'Insufficient Permissions' });
                        }
                    }
                    if (newUsername) {
                        if (mainUser.permission === 'admin' || mainUser.permission === 'moderator') {
                            User.findOne({ _id: editUser }, function(err, user) {
                                if (err) {
                                    var email = {
                                        from: 'MFA App Error, multifactorauthentification@gmail.com',
                                        to: 'multifactorauthentification@gmail.com',
                                        subject: 'Error Logged',
                                        text: 'The following error has been reported in the MFA Application: ' + err,
                                        html: 'The following error has been reported in the MFA Application:<br><br>' + err
                                    };
                                    client.sendMail(email, function(err, info) {
                                        if (err) {
                                            console.log(err);
                                        } else {
                                            console.log(info);
                                            console.log(user.email);
                                        }
                                    });
                                    res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
                                } else {
                                    if (!user) {
                                        res.json({ success: false, message: 'No user found' });
                                    } else {
                                        user.username = newUsername;
                                        user.save(function(err) {
                                            if (err) {
                                                console.log(err);
                                            } else {
                                                res.json({ success: true, message: 'Username has been updated' });
                                            }
                                        });
                                    }
                                }
                            });
                        } else {
                            res.json({ success: false, message: 'Insufficient Permissions' });
                        }
                    }
                    if (newEmail) {
                        if (mainUser.permission === 'admin' || mainUser.permission === 'moderator') {
                            User.findOne({ _id: editUser }, function(err, user) {
                                if (err) {
                                    var email = {
                                        from: 'MFA App Error, multifactorauthentification@gmail.com',
                                        to: 'multifactorauthentification@gmail.com',
                                        subject: 'Error Logged',
                                        text: 'The following error has been reported in the MFA Application: ' + err,
                                        html: 'The following error has been reported in the MFA Application:<br><br>' + err
                                    };
                                    client.sendMail(email, function(err, info) {
                                        if (err) {
                                            console.log(err);
                                        } else {
                                            console.log(info);
                                            console.log(user.email);
                                        }
                                    });
                                    res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
                                } else {
                                    if (!user) {
                                        res.json({ success: false, message: 'No user found' });
                                    } else {
                                        user.email = newEmail;
                                        user.save(function(err) {
                                            if (err) {
                                                console.log(err);
                                            } else {
                                                res.json({ success: true, message: 'E-mail has been updated' });
                                            }
                                        });
                                    }
                                }
                            });
                        } else {
                            res.json({ success: false, message: 'Insufficient Permissions' });
                        }
                    }
                    if (newPhone) {
                        if (mainUser.permission === 'admin' || mainUser.permission === 'moderator') {
                            User.findOne({ _id: editUser }, function(err, user) {
                                if (err) {
                                    var email = {
                                        from: 'MFA App Error, multifactorauthentification@gmail.com',
                                        to: 'multifactorauthentification@gmail.com',
                                        subject: 'Error Logged',
                                        text: 'The following error has been reported in the MFA Application: ' + err,
                                        html: 'The following error has been reported in the MFA Application:<br><br>' + err
                                    };
                                    client.sendMail(email, function(err, info) {
                                        if (err) {
                                            console.log(err);
                                        } else {
                                            console.log(info);
                                            console.log(user.email);
                                        }
                                    });
                                    res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
                                } else {
                                    if (!user) {
                                        res.json({ success: false, message: 'No user found' });
                                    } else {
                                        user.phone = newPhone;
                                        user.save(function(err) {
                                            if (err) {
                                                console.log(err);
                                            } else {
                                                res.json({ success: true, message: 'Phone has been updated' });
                                            }
                                        });
                                    }
                                }
                            });
                        } else {
                            res.json({ success: false, message: 'Insufficient Permissions' });
                        }
                    }
                    if (newPermission) {
                        if (mainUser.permission === 'admin' || mainUser.permission === 'moderator') {
                            User.findOne({ _id: editUser }, function(err, user) {
                                if (err) {
                                    var email = {
                                        from: 'MFA App Error, multifactorauthentification@gmail.com',
                                        to: 'multifactorauthentification@gmail.com',
                                        subject: 'Error Logged',
                                        text: 'The following error has been reported in the MFA Application: ' + err,
                                        html: 'The following error has been reported in the MFA Application:<br><br>' + err
                                    };
                                    client.sendMail(email, function(err, info) {
                                        if (err) {
                                            console.log(err);
                                        } else {
                                            console.log(info);
                                            console.log(user.email);
                                        }
                                    });
                                    res.json({ success: false, message: 'Something went wrong. This error has been logged and will be addressed by our staff. We apologize for this inconvenience!' });
                                } else {
                                    if (!user) {
                                        res.json({ success: false, message: 'No user found' });
                                    } else {
                                        if (newPermission === 'user') {
                                            if (user.permission === 'admin') {
                                                if (mainUser.permission !== 'admin') {
                                                    res.json({ success: false, message: 'Insufficient Permissions. You must be an admin to downgrade an admin.' });
                                                } else {
                                                    user.permission = newPermission;
                                                    user.save(function(err) {
                                                        if (err) {
                                                            console.log(err);
                                                        } else {
                                                            res.json({ success: true, message: 'Permissions have been updated!' });
                                                        }
                                                    });
                                                }
                                            } else {
                                                user.permission = newPermission;
                                                user.save(function(err) {
                                                    if (err) {
                                                        console.log(err);
                                                    } else {
                                                        res.json({ success: true, message: 'Permissions have been updated!' });
                                                    }
                                                });
                                            }
                                        }
                                        if (newPermission === 'moderator') {
                                            if (user.permission === 'admin') {
                                                if (mainUser.permission !== 'admin') {
                                                    res.json({ success: false, message: 'Insufficient Permissions. You must be an admin to downgrade another admin' });
                                                } else {
                                                    user.permission = newPermission;
                                                    user.save(function(err) {
                                                        if (err) {
                                                            console.log(err);
                                                        } else {
                                                            res.json({ success: true, message: 'Permissions have been updated!' });
                                                        }
                                                    });
                                                }
                                            } else {
                                                user.permission = newPermission;
                                                user.save(function(err) {
                                                    if (err) {
                                                        console.log(err);
                                                    } else {
                                                        res.json({ success: true, message: 'Permissions have been updated!' });
                                                    }
                                                });
                                            }
                                        }
                                        if (newPermission === 'admin') {
                                            if (mainUser.permission === 'admin') {
                                                user.permission = newPermission;
                                                user.save(function(err) {
                                                    if (err) {
                                                        console.log(err);
                                                    } else {
                                                        res.json({ success: true, message: 'Permissions have been updated!' });
                                                    }
                                                });
                                            } else {
                                                res.json({ success: false, message: 'Insufficient Permissions. You must be an admin to upgrade someone to the admin level' });
                                            }
                                        }
                                    }
                                }
                            });
                        } else {
                            res.json({ success: false, message: 'Insufficient Permissions' });
                        }
                    }
                }
            }
        });
    });
    return router;
};