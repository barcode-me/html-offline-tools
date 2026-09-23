const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const {readFileSync}=require('node:fs');
const {webcrypto}=require('node:crypto');
const html=readFileSync(require('node:path').join(__dirname,'../yeti-encoder-decoder.html'),'utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1].split('const input = document')[0];
const context=vm.createContext({crypto:webcrypto,TextEncoder,URL,Uint8Array,DataView,ArrayBuffer});
vm.runInContext(script,context);
function base32(text){const bits=[...Buffer.from(text)].map(v=>v.toString(2).padStart(8,'0')).join('');let result='';for(let i=0;i<bits.length;i+=5)result+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[parseInt(bits.slice(i,i+5).padEnd(5,'0'),2)];return result;}
test('matches all RFC 6238 SHA-1/256/512 vectors, including future 64-bit counters',async()=>{
 const secrets=['12345678901234567890','12345678901234567890123456789012','1234567890123456789012345678901234567890123456789012345678901234'].map(base32);
 const vectors=[[59,'94287082','46119246','90693936'],[1111111109,'07081804','68084774','25091201'],[1111111111,'14050471','67062674','99943326'],[1234567890,'89005924','91819424','93441116'],[2000000000,'69279037','90698825','38618901'],[20000000000,'65353130','77737706','47863826']];
 for(const [time,...expected] of vectors)for(const [i,algorithm] of ['SHA1','SHA256','SHA512'].entries())assert.equal(await context.generateTOTP(secrets[i],30,8,algorithm,time*1000),expected[i]);
 assert.equal(await context.generateTOTP(secrets[0].toLowerCase()+'====',30,6,'SHA-1',59000),'287082');
 assert.equal((await context.generateTOTP(secrets[0],60,10,'SHA384',59000)).length,10);
 for(const args of [['?',30,6],['A',30,6],[secrets[0],0,6],[secrets[0],30,11],[secrets[0],30,6,'SHA1junk']]) await assert.rejects(context.generateTOTP(...args));
});
test('scans lines independently and parses metadata, defaults and malformed fields',()=>{
 const secret='MDIJ4V3ANC3FQUGK3Y73YTITREAAQLWW';
 const entries=context.scanTOTPUris(`notes\notpauth://totp/ISSUER:account_name?secret=${secret}&issuer=ISSUER&algorithm=SHA1&digits=6&period=30\n otpauth://totp/A%20B%3Auser%40example.com?secret=${secret}&algorithm=SHA-256&period=60&digits=8&extra=ignored \notpauth://totp/OnlyAccount?secret=${secret}\notpauth://totp/Missing?issuer=Test\notpauth://totp/Invalid?secret=${secret}&period=no\notpauth://hotp/ignore?secret=${secret}\notpauth://totp/Duplicate?secret=${secret}&secret=ABC`);
 assert.equal(entries.length,6);assert.equal(entries[0].label,'ISSUER · account_name');assert.equal(entries[0].line,2);
 assert.equal(entries[1].label,'A B · user@example.com');assert.equal(entries[1].period,60);assert.equal(entries[1].digits,8);
 assert.equal(entries[2].algorithm,'SHA-1');assert.equal(entries[2].period,30);assert.equal(entries[2].digits,6);
 assert.match(entries[3].error,/secret/);assert.match(entries[4].error,/period/);assert.match(entries[5].error,/Duplicate/);
});
test('cards are separate, update across boundaries, and stop and clear on disposal',async()=>{
 const node=()=>({children:[],textContent:'',handlers:{},setAttribute(){},addEventListener(name,handler){this.handlers[name]=handler;},append(...items){this.children.push(...items);},appendChild(item){this.children.push(item);},replaceChildren(){this.children=[];}});
 let tick,now=59000,cleared=false,copied='';
 const ui=vm.createContext({crypto:webcrypto,TextEncoder,URL,Uint8Array,DataView,ArrayBuffer,Date:{now:()=>now},document:{createElement:node},navigator:{clipboard:{async writeText(value){copied=value;}}},setInterval(fn){tick=fn;return 1;},clearInterval(){cleared=true;}});
 vm.runInContext(script,ui);
 const container=node(), secret=base32('12345678901234567890');
 const dispose=ui.showTOTPCards(`otpauth://totp/Issuer:account?secret=${secret}\notpauth://totp/Bad?secret=INVALID!`,container);
 for(let i=0;i<30 && container.children[0].children[1].textContent==='Computing…';i++)await new Promise(resolve=>setTimeout(resolve,5));
 assert.equal(container.children.length,2);assert.equal(container.children[0].children[0].textContent,'Issuer · account');assert.equal(container.children[0].children[1].textContent,'287082');
 assert.equal(container.children[1].children[1].textContent,'Unavailable');
 assert.equal(container.children[1].children[4].disabled,true);
 const copy=container.children[0].children[4];
 assert.equal(copy.textContent,'Copy 6-digit code');assert.equal(copy.disabled,false);
 await copy.handlers.click();assert.equal(copied,'287082');assert.equal(container.children[0].children[5].textContent,'Code copied.');
 now=60000;await tick();assert.equal(container.children[0].children[1].textContent,await context.generateTOTP(secret,30,6,'SHA1',now));
 dispose();assert.equal(cleared,true);assert.equal(container.hidden,true);assert.equal(container.children.length,0);
 await tick();assert.equal(container.children.length,0);
});

test('regular secret cards start masked, reveal independently and copy original values', async () => {
 const node=()=>({children:[],textContent:'',handlers:{},setAttribute(){},addEventListener(name,handler){this.handlers[name]=handler;},append(...items){this.children.push(...items);},appendChild(item){this.children.push(item);},replaceChildren(){this.children=[];}});
 let copied;
 const ui=vm.createContext({crypto:webcrypto,TextEncoder,URL,document:{createElement:node},navigator:{clipboard:{async writeText(value){copied=value;}}}});
 vm.runInContext(script,ui);
 assert.equal(ui.maskDecodedText('abc\n秘密 👋'), '***\n****');
 const container=node();
 const dispose=ui.showTextLineCards('Password: secret:123\nplain secret\notpauth://totp/Test?secret=ABC',container);
 assert.equal(container.children.length,2);
 const [first,second]=container.children;
 assert.equal(first.children[0].textContent,'Password');
 assert.equal(first.children[1].textContent,'***********');
 const [reveal,copy]=first.children[2].children;
 await copy.handlers.click();assert.equal(copied,' secret:123');
 reveal.handlers.click();assert.equal(first.children[1].textContent,' secret:123');assert.equal(reveal.textContent,'Hide');
 assert.equal(second.children[1].textContent,'************');
 reveal.handlers.click();assert.equal(first.children[1].textContent,'***********');
 dispose();assert.equal(container.hidden,true);assert.equal(container.children.length,0);
});
