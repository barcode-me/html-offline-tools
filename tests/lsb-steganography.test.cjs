const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {webcrypto,pbkdf2Sync,createCipheriv,createHash}=require('node:crypto');
const vm=require('node:vm');
const html=readFileSync(require('node:path').join(__dirname,'../lsb-steganography.html'),'utf8');
const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
const globals={crypto:webcrypto,TextEncoder,TextDecoder,Uint8Array,Uint32Array,DataView,BigInt,Map,Blob};
const core=vm.createContext(globals);vm.runInContext(scripts[0]+';globalThis.SALT_PIXELS=SALT_PIXELS;globalThis.TYPE=TYPE;globalThis.KeystreamRng=KeystreamRng;',core);
function image(width,height,seed=1){
 const pixels=new Uint8ClampedArray(width*height*4);
 for(let i=0;i<pixels.length;i++){seed=(seed*1103515245+12345)>>>0;pixels[i]=seed>>>24;}
 for(let p=0;p<width*height;p++) pixels[p*4+3]=255;
 return pixels;
}
// Independent reference: PBKDF2 → AES-256-CTR keystream → bit-exact rejection sampling → partial Fisher–Yates.
function referencePositions(passphrase,salt,poolSize,count){
 const key=pbkdf2Sync(passphrase,salt,600000,32,'sha256');
 const stream=createCipheriv('aes-256-ctr',key,Buffer.alloc(16));
 let bytes=Buffer.alloc(0),pos=0,bitPos=0;
 const bit=()=>{if(pos>=bytes.length){bytes=stream.update(Buffer.alloc(4096));pos=0;}const b=(bytes[pos]>>(7-bitPos))&1;if(++bitPos===8){bitPos=0;pos++;}return b;};
 const uniform=n=>{if(n<=1)return 0;const w=(n-1).toString(2).length;for(;;){let v=0;for(let i=0;i<w;i++)v=v*2+bit();if(v<n)return v;}};
 const pool=Array.from({length:poolSize},(_,i)=>i),out=[];
 for(let i=0;i<count;i++){const j=i+uniform(poolSize-i);[pool[i],pool[j]]=[pool[j],pool[i]];out.push(pool[i]);}
 return out;
}
const bitsOf=bytes=>[...bytes].flatMap(b=>[7,6,5,4,3,2,1,0].map(s=>(b>>s)&1));

test('ASCII and hex payloads round trip; hex is stored as raw bytes',async()=>{
 const pixels=image(64,48);
 const text='Hello, LSB!\n\tTabs & newlines ~';
 await core.embedPayload(pixels,core.asciiBytes(text),core.TYPE.ascii,'pass phrase');
 const out=await core.extractPayload(pixels,'pass phrase');
 assert.equal(out.type,core.TYPE.ascii);assert.equal(Buffer.from(out.payload).toString('latin1'),text);
 const hex=image(64,48,7),raw=core.hexBytes('00 ff 80\n41');
 assert.deepEqual([...raw],[0,255,128,65]);
 const info=await core.embedPayload(hex,raw,core.TYPE.binary,'k');
 assert.equal(info.pixelsUsed,core.SALT_PIXELS+Math.ceil((14+4)*8/3));
 const back=await core.extractPayload(hex,'k');assert.equal(back.type,core.TYPE.binary);assert.deepEqual([...back.payload],[0,255,128,65]);
});

test('salt sits in the first N pixels and payload bits land exactly at reference Fisher–Yates positions',async()=>{
 const width=40,height=30,original=image(width,height,3),pixels=original.slice();
 const payload=core.hexBytes('deadbeef0001'),passphrase='🔑 secret';
 await core.embedPayload(pixels,payload,core.TYPE.binary,passphrase);
 const N=core.SALT_PIXELS;assert.equal(N,43);
 const salt=Buffer.alloc(16);bitsOf(new Uint8Array(16)).forEach((_,k)=>{salt[k>>3]|=(pixels[Math.floor(k/3)*4+k%3]&1)<<(7-(k&7));});
 const header=Buffer.alloc(14);header.write('STEG');header[4]=1;header[5]=1;header.writeUInt32BE(payload.length,6);createHash('sha256').update(payload).digest().copy(header,10,0,4);
 const bits=bitsOf(Buffer.concat([header,Buffer.from(payload)]));
 const positions=referencePositions(passphrase,salt,width*height-N,Math.ceil(bits.length/3));
 const touched=new Set();
 bits.forEach((b,k)=>{const off=(N+positions[Math.floor(k/3)])*4+k%3;touched.add(off);assert.equal(pixels[off]&1,b);});
 for(let k=0;k<128;k++) touched.add(Math.floor(k/3)*4+k%3);
 for(let i=0;i<pixels.length;i++) if(!touched.has(i)) assert.equal(pixels[i],original[i],'untouched byte '+i+' changed');
 for(let i=0;i<pixels.length;i++) assert.ok(Math.abs(pixels[i]-original[i])<=1);
});

test('RNG requests only the bits needed for the range',async()=>{
 const rng=await core.KeystreamRng.create(new Uint8Array(32));
 const key=Buffer.alloc(32),stream=createCipheriv('aes-256-ctr',key,Buffer.alloc(16)).update(Buffer.alloc(8));
 assert.equal(await rng.uniform(1),0);assert.equal(rng.accBits+rng.position*8,0);
 assert.equal(await rng.bits(3),stream[0]>>5);
 assert.equal(await rng.bits(13),((stream[0]&31)<<8)|stream[1]);
 assert.equal(await rng.bits(32),stream.readUInt32BE(2));
});

test('non-opaque pixels are skipped and left unchanged',async()=>{
 const pixels=image(30,30,9);
 for(let p=0;p<900;p+=3) pixels[p*4+3]=p%2?0:128;
 const before=pixels.slice();
 await core.embedPayload(pixels,core.asciiBytes('transparent-safe'),core.TYPE.ascii,'x');
 for(let p=0;p<900;p++) if(before[p*4+3]!==255) for(let c=0;c<4;c++) assert.equal(pixels[p*4+c],before[p*4+c]);
 assert.equal(Buffer.from((await core.extractPayload(pixels,'x')).payload).toString(),'transparent-safe');
});

test('fresh salt, wrong passphrase, damage, capacity and input validation',async()=>{
 const a=image(32,32),b=image(32,32);
 await core.embedPayload(a,core.asciiBytes('same'),0,'pw');await core.embedPayload(b,core.asciiBytes('same'),0,'pw');
 assert.notDeepEqual(a,b);
 await assert.rejects(core.extractPayload(a,'wrong'),/No hidden data found/);
 await assert.rejects(core.extractPayload(image(32,32,5),'pw'),/No hidden data found/);
 const cap=core.carrierLayout(image(32,32)).capacity;assert.equal(cap,Math.floor((1024-43)*3/8)-14);
 await core.embedPayload(image(32,32),new Uint8Array(cap),1,'pw');
 await assert.rejects(core.embedPayload(image(32,32),new Uint8Array(cap+1),1,'pw'),/at most/);
 await assert.rejects(core.embedPayload(image(32,32),new Uint8Array(0),1,'pw'),/Enter data/);
 assert.throws(()=>core.carrierLayout(image(6,7)),/more than 43/);
 const damaged=image(32,32);await core.embedPayload(damaged,core.asciiBytes('x'.repeat(200)),0,'pw');
 const flips=[];for(let off=43*4;off<damaged.length&&flips.length<4000;off++) if(off%4!==3){damaged[off]^=1;flips.push(off);}
 await assert.rejects(core.extractPayload(damaged,'pw'));
 assert.throws(()=>core.asciiBytes('café'),/Only ASCII/);
 for(const bad of ['0','0x00','fg','00:ff']) assert.throws(()=>core.hexBytes(bad),/Hex input/);
});
