// Runs only in the managed browser profile. Uses its pinned Playwright installation.
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require(require.resolve('playwright-core', { paths: ['/opt/codex-browser-helper'] }));
let browserStage='startup';

(async () => {
  const root = path.resolve(__dirname, '..');
  const fixture = path.resolve(root, process.env.CARGO_TARGET_DIR || 'target', 'debug/examples/ui_fixture');
  const output = path.join(process.env.CODEX_TMP_DIR, 'playwright');
  fs.mkdirSync(output, { recursive: true });
  const child = spawn(fixture, [], {stdio:['ignore','ignore','inherit','pipe']});
  let browser, publicServer, liveChild;
  try {
    const url = await new Promise((resolve,reject) => {
      let address='';
      child.stdio[3].on('data',data => {address += data.toString(); if(address.includes('\n')) resolve(address.trim());});
      child.once('exit',code=>reject(new Error(`fixture server exited (${code})`)));
      child.once('error',reject);
    });
    const origin = new URL(url).origin;
    browserStage='simulation';
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
    await page.selectOption('#method','getblockcount');
    await page.locator('#run').click();
    await page.waitForFunction(()=>!document.getElementById('run').disabled);
    assert.equal(await page.locator('#block-height').textContent(),'State at block 42');
    assert.equal(await page.locator('#block-hash').textContent(),'a'.repeat(64));
    assert.deepEqual((await readReport()).result.chain_context,{height:42,hash:'a'.repeat(64)});
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
      assert.equal(await page.locator('#block-context').isHidden(),true);
      assert.equal(await page.locator('#block-hash').textContent(),'');
    }
    await page.selectOption('#scenario','fixture');
    await page.locator('#run').click();
    await page.waitForFunction(()=>!document.getElementById('run').disabled);
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
    await page.locator('#result').scrollIntoViewIfNeeded();
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    await page.screenshot({path:path.join(output,'m0-mobile.png'),fullPage:true});
    assert.ok(network.every(address=>new URL(address).origin===origin));
    assert.deepEqual(errors,[]);
    assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
    assert.equal((await context.serviceWorkers()).length,0);
    // Live dashboard uses the same native core. With no reviewed release it
    // must show blocked status and never contact the configured SOCKS port.
    browserStage='live-startup';
    liveChild=spawn(fixture, [], {
      env:{...process.env,ZRPC_BROWSER_LIVE:'1'},stdio:['ignore','ignore','inherit','pipe']
    });
    const liveUrl=await new Promise((resolve,reject)=>{
      let address='';
      liveChild.stdio[3].on('data',data=>{address+=data.toString();if(address.includes('\n'))resolve(address.trim());});
      liveChild.once('exit',code=>reject(new Error(`live fixture exited (${code})`)));
      liveChild.once('error',reject);
    });
    const liveOrigin=new URL(liveUrl).origin;
    const livePage=await context.newPage(); const liveRequests=[]; const liveBodies=[]; const liveErrors=[];
    livePage.on('request',req=>{
      liveRequests.push(req.url());
      if(new URL(req.url()).pathname==='/api/query') liveBodies.push(req.postDataJSON());
    });
    livePage.on('pageerror',()=>liveErrors.push('browser exception'));
    await livePage.goto(liveUrl);
    browserStage='live-bootstrap';
    await livePage.getByText('Local session ready.',{exact:false}).waitFor();
    assert.equal(await livePage.locator('#mode-label').textContent(),'LIVE CLIENT · UNVERIFIED');
    assert.equal(await livePage.locator('#scenario').isHidden(),true);
    await livePage.locator('#run').click();
    browserStage='live-query';
    await livePage.waitForFunction(() => {
      if (document.getElementById('run').disabled) return false;
      try {
        return JSON.parse(document.getElementById('result').textContent).mode === 'private_blocked';
      } catch {
        return false;
      }
    });
    await livePage.locator('#result-label').filter({hasText:'PRIVATE MODE BLOCKED'}).waitFor();
    const blocked=JSON.parse(await livePage.locator('#result').textContent());
    assert.equal(blocked.private_accepted,false);
    assert.equal(blocked.query_sent,false);
    assert.equal(blocked.simulation,false);
    assert.equal(blocked.error.code,'unknown_release');
    browserStage='live-methods';
    const tryLiveMethod=async(method,params)=>{
      if(await livePage.locator('#method').inputValue()!==method){
        await livePage.selectOption('#method',method);
      }
      const before=liveBodies.length;
      await livePage.locator('#run').click();
      await livePage.waitForFunction(()=>!document.getElementById('run').disabled);
      assert.equal(liveBodies.length,before+1);
      assert.deepEqual(liveBodies.at(-1),{jsonrpc:'2.0',id:1,method,params});
      const report=JSON.parse(await livePage.locator('#result').textContent());
      assert.equal(report.mode,'private_blocked');
      assert.equal(report.private_accepted,false);
      assert.equal(report.query_sent,false);
    };
    await livePage.selectOption('#method','getblockhash');
    assert.equal(await livePage.locator('#height-param').isVisible(),true);
    await livePage.locator('#height').fill('2147483648');
    const beforeBadHeight=liveBodies.length;
    await livePage.locator('#run').click();
    assert.equal(liveBodies.length,beforeBadHeight);
    assert.match(await livePage.locator('#session').textContent(),/whole block height/);
    await livePage.locator('#height').fill('123');
    await tryLiveMethod('getblockhash',[123]);
    await livePage.selectOption('#method','getblockheader');
    assert.equal(await livePage.locator('#hash-param').isVisible(),true);
    await livePage.locator('#hash').fill('bad');
    const beforeBadHash=liveBodies.length;
    await livePage.locator('#run').click();
    assert.equal(liveBodies.length,beforeBadHash);
    assert.match(await livePage.locator('#session').textContent(),/64-digit hexadecimal/);
    await livePage.locator('#hash').fill('a'.repeat(64));
    await livePage.selectOption('#verbosity','true');
    await tryLiveMethod('getblockheader',['a'.repeat(64),true]);
    await livePage.selectOption('#method','getrawtransaction');
    await livePage.locator('#hash').fill('b'.repeat(64));
    await livePage.selectOption('#verbosity','false');
    await tryLiveMethod('getrawtransaction',['b'.repeat(64),false]);
    await tryLiveMethod('getblockcount',[]);
    await tryLiveMethod('getblockchaininfo',[]);
    await livePage.selectOption('#method','getrawtransaction');
    await livePage.screenshot({path:path.join(output,'live-blocked-desktop.png'),fullPage:true});
    browserStage='live-mobile';
    await livePage.setViewportSize({width:390,height:844});
    assert.ok(await livePage.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
    await livePage.screenshot({path:path.join(output,'live-blocked-mobile.png'),fullPage:true});
    assert.ok(liveRequests.every(address=>new URL(address).origin===liveOrigin));
    assert.deepEqual(liveErrors,[]);
    // Static public site: scripts/remote resources are absent, even on interaction.
    browserStage='public-site';
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
    if(liveChild)liveChild.kill();
    child.kill();
  }
})().catch(()=>{console.error(`Browser contract check failed at ${browserStage}; bootstrap capability intentionally omitted from diagnostics.`);process.exitCode=1;});
