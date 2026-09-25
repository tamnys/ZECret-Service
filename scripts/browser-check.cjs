// Runs only in the managed browser profile. Uses its pinned Playwright installation.
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require(require.resolve('playwright-core', { paths: ['/opt/codex-browser-helper'] }));

(async () => {
  const root = path.resolve(__dirname, '..');
  const output = path.join(process.env.CODEX_TMP_DIR, 'playwright');
  fs.mkdirSync(output, { recursive: true });
  const child = spawn(path.join(root, 'target/debug/examples/ui_fixture'), [], {stdio:['ignore','ignore','inherit','pipe']});
  let browser, publicServer;
  try {
    const url = await new Promise((resolve,reject) => {
      let address='';
      child.stdio[3].on('data',data => {address += data.toString(); if(address.includes('\n')) resolve(address.trim());});
      child.once('exit',code=>reject(new Error(`fixture server exited (${code})`)));
      child.once('error',reject);
    });
    const origin = new URL(url).origin;
    browser = await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
    const context = await browser.newContext({viewport:{width:1440,height:1100}});
    const page=await context.newPage();
    const network=[]; const errors=[];
    page.on('request',req=>network.push(req.url()));
    page.on('pageerror',()=>errors.push('browser exception'));
    await page.goto(url);
    await page.getByText('Local session ready.',{exact:false}).waitFor();
    assert.equal(new URL(page.url()).hash,'');
    const readReport=async()=>JSON.parse(await page.locator('#result').textContent());
    await page.locator('#run').click();
    await page.locator('#result-label').filter({hasText:'SYNTHETIC RESULT'}).waitFor();
    assert.equal((await readReport()).private_accepted,false);
    assert.equal((await readReport()).query_sent,false);
    assert.equal((await readReport()).fixture_dispatched,true);
    // Check each method, including distinct transaction/block fixture identifiers.
    for(const method of ['getblockchaininfo','getblockhash','getblockheader','getrawtransaction']){
      await page.selectOption('#method',method);
      await page.locator('#run').click();
      await page.waitForFunction(()=>!document.getElementById('run').disabled);
      assert.equal((await readReport()).error,null);
    }
    await page.screenshot({path:path.join(output,'m0-desktop.png'),fullPage:true});
    for(const scenario of ['unknown-release','wrong-key','invalid-nonce','altered-event-log','tor-unavailable','node-unavailable']){
      await page.selectOption('#scenario',scenario);
      await page.locator('#run').click();
      await page.waitForFunction(()=>!document.getElementById('run').disabled);
      const report=await readReport();
      assert.equal(report.private_accepted,false);
      assert.equal(report.query_sent,false);
      if(scenario!=='node-unavailable') assert.equal(report.fixture_dispatched,false);
      assert.ok(report.error);
    }
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
    await page.locator('#result').scrollIntoViewIfNeeded();
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    await page.screenshot({path:path.join(output,'m0-mobile.png'),fullPage:true});
    assert.ok(network.every(address=>new URL(address).origin===origin));
    assert.deepEqual(errors,[]);
    assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
    assert.equal((await context.serviceWorkers()).length,0);
    // Static public site: scripts/remote resources are absent, even on interaction.
    publicServer=http.createServer((request,response)=>{
      const file=request.url==='/'?'index.html':request.url==='/style.css'?'style.css':null;
      if(!file){response.writeHead(404);return response.end();}
      response.setHeader('Content-Type',file.endsWith('.css')?'text/css':'text/html');
      response.end(fs.readFileSync(path.join(root,'ui/public',file)));
    });
    await new Promise(resolve=>publicServer.listen(0,'127.0.0.1',resolve));
    const publicOrigin=`http://127.0.0.1:${publicServer.address().port}`;
    const publicPage=await context.newPage(); const publicRequests=[];
    publicPage.on('request',req=>publicRequests.push(req.url()));
    await publicPage.goto(publicOrigin);
    assert.equal(await publicPage.locator('script,input,form,iframe').count(),0);
    assert.ok(publicRequests.every(address=>new URL(address).origin===publicOrigin));
    await publicPage.setViewportSize({width:1440,height:1100});
    await publicPage.screenshot({path:path.join(output,'public-desktop.png'),fullPage:true});
    await publicPage.setViewportSize({width:390,height:844});
    assert.ok(await publicPage.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
    await publicPage.screenshot({path:path.join(output,'public-mobile.png'),fullPage:true});
    console.log('Browser checks passed: local methods/scenarios, loopback requests, fragment removal, no storage, public static boundary, desktop/mobile.');
  } finally {
    if(browser)await browser.close();
    if(publicServer)await new Promise(resolve=>publicServer.close(resolve));
    child.kill();
  }
})().catch(()=>{console.error('Browser contract check failed; bootstrap capability intentionally omitted from diagnostics.');process.exitCode=1;});
