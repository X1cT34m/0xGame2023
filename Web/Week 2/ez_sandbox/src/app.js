const crypto = require('crypto')
const vm = require('vm');

const express = require('express')
const session = require('express-session')
const bodyParser = require('body-parser')

var app = express()

app.use(bodyParser.json())
app.use(session({
    secret: crypto.randomBytes(64).toString('hex'),
    resave: false,
    saveUninitialized: true
}))

var users = {}
var admins = {}

function merge(target, source) {
    for (let key in source) {
        if (key === '__proto__') {
            continue
        }
        if (key in source && key in target) {
            merge(target[key], source[key])
        } else {
            target[key] = source[key]
        }
    }
    return target
}

function clone(source) {
    return merge({}, source)
}

function waf(code) {
    let blacklist = ['constructor', 'mainModule', 'require', 'child_process', 'process', 'exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']
    for (let v of blacklist) {
        if (code.includes(v)) {
            throw new Error(v + ' is banned')
        }
    }
}

function requireLogin(req, res, next) {
    if (!req.session.user) {
        res.redirect('/login')
    } else {
        next()
    }
}

app.use(function(req, res, next) {
    for (let key in Object.prototype) {
        delete Object.prototype[key]
    }
    next()
})

app.get('/', requireLogin, function(req, res) {
    res.sendFile(__dirname + '/public/index.html')
})

app.get('/login', function(req, res) {
    res.sendFile(__dirname + '/public/login.html')
})

app.get('/register', function(req, res) {
    res.sendFile(__dirname + '/public/register.html')
})

app.post('/login', function(req, res) {
    let { username, password } = clone(req.body)

    if (username in users && password === users[username]) {
        req.session.user = username

        if (username in admins) {
            req.session.role = 'admin'
        } else {
            req.session.role = 'guest'
        }

        res.send({
            'message': 'login success'
        })
    } else {
        res.send({
            'message': 'login failed'
        })
    }
})

app.post('/register', function(req, res) {
    let { username, password } = clone(req.body)

    if (username in users) {
        res.send({
            'message': 'register failed'
        })
    } else {
        users[username] = password
        res.send({
            'message': 'register success'
        })
    }
})

app.get('/profile', requireLogin, function(req, res) {
    res.send({
        'user': req.session.user,
        'role': req.session.role
    })
})

app.post('/sandbox', requireLogin, function(req, res) {
    if (req.session.role === 'admin') {
        let code = req.body.code
        let sandbox = Object.create(null)
        let context = vm.createContext(sandbox)
        
        try {
            waf(code)
            let result = vm.runInContext(code, context)
            res.send({
                'result': result
            })
        } catch (e) {
            res.send({
                'result': e.message
            })
        }
    } else {
        res.send({
            'result': 'Your role is not admin, so you can not run any code'
        })
    }
})

app.get('/logout', requireLogin, function(req, res) {
    req.session.destroy()
    res.redirect('/login')
})

app.listen(3000, function() {
    console.log('server start listening on :3000')
})