const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const axios = require('axios');
const crypto = require('crypto');

const settings = JSON.parse(fs.readFileSync('settings.json', 'utf8'));

const app = express();
const port = 3001;

let monitors = [];

// Configure Passport for Discord authentication
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new DiscordStrategy({
    clientID: settings.clientID,
    clientSecret: settings.clientSecret,
    callbackURL: settings.callbackURL,
    scope: ['identify', 'email', 'guilds']
}, (accessToken, refreshToken, profile, done) => process.nextTick(() => done(null, profile))));

// Middleware setup
app.use(session({
    secret: 'some-random-secret',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(path.join(__dirname, 'public')));

const monitorFolder = path.join(__dirname, 'monitors');
const uptimePagesFolder = path.join(__dirname, 'uptime-pages');
const apiKeysFolder = path.join(__dirname, 'api-keys');

if (!fs.existsSync(monitorFolder)) fs.mkdirSync(monitorFolder);
if (!fs.existsSync(uptimePagesFolder)) fs.mkdirSync(uptimePagesFolder);
if (!fs.existsSync(apiKeysFolder)) fs.mkdirSync(apiKeysFolder);

app.get('/', (req, res) => res.render('index', { user: req.user }));

app.get('/auth/discord', passport.authenticate('discord'));

app.get('/auth/discord/callback', passport.authenticate('discord', { failureRedirect: '/' }), (req, res) => res.redirect('/home'));

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Error logging out:', err);
            return res.redirect('/');
        }
        res.redirect('/');
    });
});

app.get('/home', (req, res) => {
    if (req.isAuthenticated()) {
        const userMonitorsFile = `monitors/monitor-${req.user.username}.json`;
        if (fs.existsSync(userMonitorsFile)) {
            monitors = JSON.parse(fs.readFileSync(userMonitorsFile, 'utf8'));
        }
        res.render('home', { user: req.user, monitors: monitors });
    } else {
        res.redirect('/');
    }
});

app.post('/add-monitor', (req, res) => {
    const { name, url, webhookUrl } = req.body;
    const id = monitors.length ? monitors[monitors.length - 1].id + 1 : 1;
    const monitor = { id, name, url, interval: 60, lastStatus: 'unknown', notifications: { webhookUrl } };
    monitors.push(monitor);

    const userMonitorsFile = `monitors/monitor-${req.user.username}.json`;
    fs.writeFileSync(userMonitorsFile, JSON.stringify(monitors, null, 2));

    scheduleMonitorCheck(monitor);

    res.redirect('/home');
});

app.post('/edit-monitor', (req, res) => {
    const { monitorId, name, url, webhookUrl } = req.body;
    
    const monitor = monitors.find(m => m.id == monitorId);
    if (monitor) {
        monitor.name = name;
        monitor.url = url;
        monitor.notifications.webhookUrl = webhookUrl;

        const userMonitorsFile = `monitors/monitor-${req.user.username}.json`;
        fs.writeFileSync(userMonitorsFile, JSON.stringify(monitors, null, 2));
        
        res.redirect('/home');
    } else {
        res.status(404).send('Monitor not found');
    }
});

app.post('/remove-monitor', (req, res) => {
    const { monitorId } = req.body;
    monitors = monitors.filter(monitor => monitor.id != monitorId);

    const userMonitorsFile = `monitors/monitor-${req.user.username}.json`;
    fs.writeFileSync(userMonitorsFile, JSON.stringify(monitors, null, 2));

    res.redirect('/home');
});

// Route for viewing the API key
app.get('/api-key', (req, res) => {
    if (req.isAuthenticated()) {
        const userApiKeyFile = `api-keys/api-key-${req.user.username}.json`;
        let apiKey = null;
        if (fs.existsSync(userApiKeyFile)) {
            const apiKeyData = JSON.parse(fs.readFileSync(userApiKeyFile, 'utf8'));
            apiKey = apiKeyData.apiKey;
        }
        res.render('api-key', { user: req.user, apiKey: apiKey });
    } else {
        res.redirect('/');
    }
});

// Route for generating a new API key
app.post('/create-api-key', (req, res) => {
    if (req.isAuthenticated()) {
        const apiKey = crypto.randomBytes(20).toString('hex');
        const userApiKeyFile = `api-keys/api-key-${req.user.username}.json`;
        fs.writeFileSync(userApiKeyFile, JSON.stringify({ apiKey }, null, 2));
        res.redirect('/api-key');
    } else {
        res.redirect('/');
    }
});

// Route for removing an API key
app.post('/remove-api-key', (req, res) => {
    if (req.isAuthenticated()) {
        const userApiKeyFile = `api-keys/api-key-${req.user.username}.json`;
        if (fs.existsSync(userApiKeyFile)) {
            fs.unlinkSync(userApiKeyFile);
        }
        res.redirect('/api-key');
    } else {
        res.redirect('/');
    }
});

app.post('/set-notifications', (req, res) => {
    const { monitorId, webhookUrl } = req.body;
    
    const monitor = monitors.find(m => m.id == monitorId);
    if (monitor) {
        monitor.notifications.webhookUrl = webhookUrl;

        const userMonitorsFile = `monitors/monitor-${req.user.username}.json`;
        fs.writeFileSync(userMonitorsFile, JSON.stringify(monitors, null, 2));
    }
    
    res.redirect('/home');
});

app.post('/test-webhook', async (req, res) => {
    const { webhookUrl } = req.body;
    try {
        await axios.post(webhookUrl, {
            embeds: [
                {
                    title: "Uptime Notification",
                    color: 3066993, // Green color
                    description: "Webhook test message",
                    footer: {
                        text: "VixUP 2024"
                    }
                }
            ]
        });
        res.json({ message: 'Webhook test message sent successfully.' });
    } catch (error) {
        console.error('Error testing webhook:', error);
        res.json({ message: 'Error testing webhook.' });
    }
});

const scheduleMonitorCheck = (monitor) => {
    setInterval(async () => {
        try {
            const start = Date.now();
            const response = await axios.get(monitor.url);
            const ping = Date.now() - start;
            const status = response.status === 200 ? 'up' : 'down';
            monitor.lastStatus = status;
            console.log(`Monitor ${monitor.name} is ${status}`);
            
            if (monitor.notifications.webhookUrl) {
                await axios.post(monitor.notifications.webhookUrl, {
                    embeds: [
                        {
                            title: "Uptime Notification",
                            color: status === 'up' ? 3066993 : 15158332, // Green for up, Red for down
                            description: `Service ${monitor.name} is ${status}!`,
                            fields: [
                                {
                                    name: "URL",
                                    value: monitor.url
                                },
                                {
                                    name: "Ping",
                                    value: `${ping}ms`
                                }
                            ],
                            footer: {
                                text: "VixUP 2024"
                            }
                        }
                    ]
                });
            }
        } catch (error) {
            monitor.lastStatus = 'down';
            console.error(`Error checking monitor ${monitor.name}:`, error);
            
            if (monitor.notifications.webhookUrl) {
                await axios.post(monitor.notifications.webhookUrl, {
                    embeds: [
                        {
                            title: "Uptime Notification",
                            color: 15158332, // Red color
                            description: `Service ${monitor.name} is down!`,
                            fields: [
                                {
                                    name: "URL",
                                    value: monitor.url
                                },
                                {
                                    name: "Ping",
                                    value: `N/A`
                                }
                            ],
                            footer: {
                                text: "VixUP 2024"
                            }
                        }
                    ]
                });
            }
        }
    }, monitor.interval * 1000);
};

// Middleware pentru gestionarea erorilor 404
app.use((req, res, next) => {
    res.status(404).render('404');
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
