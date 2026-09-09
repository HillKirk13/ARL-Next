const http = require('http');
const puppeteer = require('puppeteer-core');
const fs = require('fs');
const path = require('path');

const wappalyzerCode = fs.readFileSync(path.join(__dirname, 'wappalyzer.js'), 'utf8');
const vm = require('vm');
const wappalyzerScript = new vm.Script(wappalyzerCode);
const json = JSON.parse(fs.readFileSync(path.join(__dirname, 'apps.json'), 'utf8'));

let browser;

async function initBrowser() {
    browser = await puppeteer.launch({
        executablePath: '/usr/bin/chromium',
        args: [
            '--no-sandbox', 
            '--disable-setuid-sandbox', 
            '--disable-dev-shm-usage', 
            '--ignore-certificate-errors', 
            '--disable-gpu'
        ],
        ignoreHTTPSErrors: true
    });
}

function analyzeUrl(url) {
    return new Promise(async (resolve, reject) => {
        let page;
        let context;
        let timeoutId;

        const cleanupAndResolve = async (apps) => {
            if (timeoutId) clearTimeout(timeoutId);
            if (page) await page.close().catch(() => true);
            if (context) await context.close().catch(() => true);
            resolve({ url: url, originalUrl: url, applications: apps || [] });
        };

        timeoutId = setTimeout(() => {
            console.log(`[Timeout] 32s limit reached for ${url}`);
            cleanupAndResolve([]);
        }, 15000);
        try {
            // Create a new incognito context for isolation
            context = await browser.createIncognitoBrowserContext();
            page = await context.newPage();
            
            // Bypass WAF by mocking User-Agent and webdriver
            await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
            await page.evaluateOnNewDocument(() => {
                Object.defineProperty(navigator, 'webdriver', { get: () => false });
            });

            await page.setViewport({ width: 1280, height: 1024 });

            // Resource blocking to save CPU and Bandwidth
            await page.setRequestInterception(true);
            page.on('request', (req) => {
                const resourceType = req.resourceType();
                if (['image', 'stylesheet', 'font', 'media'].includes(resourceType)) {
                    req.abort();
                } else {
                    req.continue();
                }
            });

            let headers = {};
            let html = '';

            page.on('response', response => {
                // We want the headers from the main document response
                if (response.url().replace(/\/$/, '') === url.replace(/\/$/, '') || response.url() === url) {
                    const contentType = response.headers()['content-type'];
                    if (response.status() === 200 && contentType && contentType.includes('text/html')) {
                        headers = response.headers();
                    }
                }
            });

            try {
                await page.goto(url, { waitUntil: 'networkidle2', timeout: 25000 });
            } catch (e) {
                // timeout is fine, we might still have DOM
            }

            html = await page.content();
            
            // Truncate huge HTML to avoid regex explosion in wappalyzer
            if (html.length > 50000) {
                html = html.substring(0, 25000) + html.substring(html.length - 25000, html.length);
            }

            const environmentVarsArray = await page.evaluate(() => {
                return Object.keys(window);
            });
            const environmentVars = environmentVarsArray.slice(0, 500).join(' ');

            // Close page and context
            await page.close();
            await context.close();

            // Evaluate Wappalyzer using a precompiled vm.Script to save massive CPU cycles while maintaining state isolation
            const contextObj = {};
            vm.createContext(contextObj);
            wappalyzerScript.runInContext(contextObj);
            const wappalyzer = contextObj.wappalyzer;

            wappalyzer.apps = json.apps;
            wappalyzer.categories = json.categories;

            wappalyzer.driver = {
                log: function(args) { },
                displayApps: function() {
                    let apps = [];
                    for (let app in wappalyzer.detected[url]) {
                        let cats = [];
                        wappalyzer.apps[app].cats.forEach(function(cat) {
                            cats.push(wappalyzer.categories[cat].name);
                        });
                        apps.push({
                            name: app,
                            confidence: wappalyzer.detected[url][app].confidenceTotal.toString(),
                            version: wappalyzer.detected[url][app].version,
                            icon: wappalyzer.apps[app].icon || 'default.svg',
                            website: wappalyzer.apps[app].website,
                            categories: cats
                        });
                    }
                    this.sendResponse(apps);
                },
                sendResponse: function(apps) {
                    cleanupAndResolve(apps);
                }
            };

            const parsedUrl = new URL(url);
            wappalyzer.analyze(parsedUrl.hostname, url, {
                html: html,
                headers: headers,
                env: environmentVars
            });

        } catch (e) {
            cleanupAndResolve([]);
        }
    });
}

async function takeScreenshot(url) {
    return new Promise(async (resolve, reject) => {
        let page;
        let context;
        let timeoutId;

        const cleanupAndResolve = async (base64) => {
            if (timeoutId) clearTimeout(timeoutId);
            if (page) await page.close().catch(() => true);
            if (context) await context.close().catch(() => true);
            resolve({ url: url, base64: base64 || null });
        };

        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            console.error(`[Security Block] Invalid protocol for URL: ${url}`);
            resolve({ url: url, base64: null });
            return;
        }

        timeoutId = setTimeout(() => {
            console.log(`[Screenshot Timeout] 25s limit reached for ${url}`);
            cleanupAndResolve(null);
        }, 25000);
        
        try {
            context = await browser.createIncognitoBrowserContext();
            page = await context.newPage();
            
            // Bypass WAF by mocking User-Agent and webdriver
            await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
            await page.evaluateOnNewDocument(() => {
                Object.defineProperty(navigator, 'webdriver', { get: () => false });
            });
            
            page.on('dialog', async dialog => {
                await dialog.dismiss().catch(() => {});
            });

            await page.setRequestInterception(true);
            page.on('request', (req) => {
                if (req.isInterceptResolutionHandled && req.isInterceptResolutionHandled()) return;
                const rt = req.resourceType();
                if (['media', 'font', 'websocket', 'manifest'].includes(rt)) {
                    req.abort().catch(() => {});
                } else {
                    req.continue().catch(() => {});
                }
            });

            await page.setViewport({ width: 1024, height: 768 });

            const gotoPromise = page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });
            gotoPromise.catch(() => {});
            
            let gotoTimeoutId;
            const timeoutPromise = new Promise((_, reject) => {
                gotoTimeoutId = setTimeout(() => reject(new Error('Goto Hard Timeout')), 15000);
            });
            
            try {
                await Promise.race([gotoPromise, timeoutPromise]);
            } catch (gotoErr) {
                console.error(`Goto warning [${url}]:`, gotoErr.message);
            } finally {
                clearTimeout(gotoTimeoutId);
            }
            
            await new Promise(r => setTimeout(r, 3000));

            let height = 768;
            try {
                const evalPromise = page.evaluate(() => {
                    if (document.body) { document.body.style.backgroundColor = 'white'; }
                    try {
                        let style = document.createElement('style');
                        style.innerHTML = 'html, body { height: auto !important; overflow: visible !important; min-height: 100% !important; }';
                        document.head.appendChild(style);
                    } catch(e) {}
                    
                    let maxH = 768;
                    try {
                        maxH = Math.max(
                            document.body ? document.body.scrollHeight : 768,
                            document.documentElement ? document.documentElement.scrollHeight : 768,
                            document.body ? document.body.offsetHeight : 768,
                            document.documentElement ? document.documentElement.offsetHeight : 768,
                            document.body ? document.body.clientHeight : 768,
                            document.documentElement ? document.documentElement.clientHeight : 768
                        );
                    } catch(e) {}
                    
                    return maxH > 2048 ? 2048 : (maxH < 768 ? 768 : maxH);
                });
                evalPromise.catch(() => {}); 
                
                let evalTimeoutId;
                const evalTimeout = new Promise((_, reject) => {
                    evalTimeoutId = setTimeout(() => reject(new Error('Evaluate Timeout')), 5000);
                });
                
                height = await Promise.race([evalPromise, evalTimeout]);
                if (typeof height !== 'number') height = 768;
                clearTimeout(evalTimeoutId); 
            } catch (evalErr) {
                console.error(`Evaluate warning [${url}]:`, evalErr.message);
                height = 768;
            }

            try {
                await page.setViewport({ width: 1024, height: height });
            } catch(vpErr) {}
            
            let base64 = null;
            try {
                base64 = await page.screenshot({ type: 'jpeg', quality: 30, encoding: 'base64' });
            } catch (ssErr) {
                console.error(`Screenshot error [${url}]:`, ssErr.message);
                await new Promise(r => setTimeout(r, 1000));
                try {
                    await page.setViewport({ width: 1024, height: 768 });
                    base64 = await page.screenshot({ type: 'jpeg', quality: 30, encoding: 'base64', clip: {x: 0, y: 0, width: 1024, height: 768} });
                } catch (ssErr2) {
                    console.error(`Screenshot fallback error [${url}]:`, ssErr2.message);
                }
            }
            cleanupAndResolve(base64);
        } catch (e) {
            console.error(`Screenshot error [${url}]:`, e.message);
            cleanupAndResolve(null);
        }
    });
}

let requestsCount = 0;
let isRestartingBrowser = false;
const MAX_REQUESTS = 50; // Self-heal to prevent memory leaks

async function checkShutdown() {
    if (requestsCount >= MAX_REQUESTS && !isRestartingBrowser) {
        isRestartingBrowser = true;
        requestsCount = 0; // Reset for the new browser
        console.log('Max requests reached, performing rolling restart of browser instance...');
        
        const oldBrowser = browser;
        
        try {
            browser = await puppeteer.launch({
                executablePath: '/usr/bin/chromium',
                args: [
                    '--no-sandbox', 
                    '--disable-setuid-sandbox', 
                    '--disable-dev-shm-usage', 
                    '--ignore-certificate-errors', 
                    '--disable-gpu'
                ],
                ignoreHTTPSErrors: true
            });
            console.log('New browser spawned. Retiring old browser in background...');
        } catch (e) {
            console.error('Failed to launch new browser during rotation:', e);
            browser = oldBrowser; // Revert to old if failed
        }

        isRestartingBrowser = false;

        if (browser !== oldBrowser) {
            // Give the old browser exactly 35 seconds to finish its pending tasks, then kill
            setTimeout(() => {
                console.log('Cleaning up retired browser...');
                if (oldBrowser) {
                    oldBrowser.close().catch(() => true);
                    // Double tap to avoid zombies if close() hangs
                    if (oldBrowser.process() && oldBrowser.process().pid) {
                        try {
                            process.kill(oldBrowser.process().pid, 'SIGKILL');
                        } catch(e) {}
                    }
                }
            }, 35000);
        }
    }
}

const server = http.createServer(async (req, res) => {
    if (req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', async () => {
            try {
                const data = JSON.parse(body);
                const url = data.url;
                if (!url) {
                    res.writeHead(400);
                    res.end('Missing url');
                    return;
                }
                
                let result;
                if (req.url === '/screenshot') {
                    result = await takeScreenshot(url);
                } else {
                    result = await analyzeUrl(url);
                }
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(result));
                
                requestsCount++;
            } catch (e) {
                res.writeHead(500);
                res.end(e.message);
            } finally {
                checkShutdown();
            }
        });
    } else {
        res.writeHead(200);
        res.end('Puppeteer Wappalyzer Server OK');
        checkShutdown();
    }
});

initBrowser().then(() => {
    server.listen(5005, '0.0.0.0', () => {
        console.log('Puppeteer server running on port 5005');
    });
}).catch(console.error);
