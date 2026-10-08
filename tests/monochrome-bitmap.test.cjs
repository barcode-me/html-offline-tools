const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {webcrypto,pbkdf2Sync,createCipheriv,createHash}=require('node:crypto');
const vm=require('node:vm');
const html=readFileSync(require('node:path').join(__dirname,'../monochrome-bitmap.html'),'utf8');
const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
const core=vm.createContext({Uint8Array,Uint32Array,Float32Array,DataView,crypto:webcrypto,TextEncoder,BigInt,Map,btoa,atob});
const coreScript=scripts.find(script=>script.includes('const BMP ='));
vm.runInContext(scripts.find(script=>script.includes('var qrcode =')),core);
vm.runInContext(coreScript+';globalThis.HIDE=HIDE;globalThis.PAYLOAD=PAYLOAD;globalThis.QR_CAPACITY=QR_CAPACITY;globalThis.MIN_PIXELS=MIN_PIXELS;',core);
// Independent reader for 1-bit BITMAPINFOHEADER files.
function readBmp(buf){
 const b=Buffer.from(buf);
 assert.equal(b.toString('latin1',0,2),'BM');assert.equal(b.readUInt32LE(2),b.length);
 const offset=b.readUInt32LE(10),width=b.readInt32LE(18),height=b.readInt32LE(22);
 assert.equal(b.readUInt32LE(14),40);assert.equal(b.readUInt16LE(26),1);assert.equal(b.readUInt16LE(28),1);assert.equal(b.readUInt32LE(30),0);
 assert.deepEqual([...b.subarray(54,62)],[0,0,0,0,255,255,255,0]);
 const stride=Math.ceil(width/32)*4;assert.equal(b.length,offset+stride*height);assert.equal(b.readUInt32LE(34),stride*height);
 const pixels=[];
 for(let y=0;y<height;y++){const row=offset+(height-1-y)*stride;for(let x=0;x<width;x++)pixels.push((b[row+(x>>3)]>>(7-(x&7)))&1);
  for(let x=width;x<stride*8;x++) assert.equal((b[row+(x>>3)]>>(7-(x&7)))&1,0,'row padding must be zero');}
 return {width,height,pixels};
}
test('BMP header, bottom-up rows, MSB-first bits and 4-byte row padding',()=>{
 for(const [w,h] of [[1,1],[7,3],[8,2],[31,4],[32,1],[33,5],[100,7]]){
  const bits=Uint8Array.from({length:w*h},(_,i)=>(i*7+(i>>3))%3===0?1:0);
  const parsed=readBmp(core.encodeBmp(bits,w,h));
  assert.equal(parsed.width,w);assert.equal(parsed.height,h);assert.deepEqual(parsed.pixels,[...bits]);
 }
 assert.throws(()=>core.encodeBmp(new Uint8Array(0),0,1),/Invalid bitmap size/);
});
test('grayscale uses Rec. 709 luma and composites transparency over white',()=>{
 const g=core.grayscale(new Uint8Array([255,0,0,255, 0,255,0,255, 0,0,255,255, 0,0,0,0, 0,0,0,128]));
 assert.ok(Math.abs(g[0]-54.213)<.01);assert.ok(Math.abs(g[1]-182.376)<.01);assert.ok(Math.abs(g[2]-18.411)<.01);
 assert.equal(g[3],255);assert.ok(Math.abs(g[4]-255*(127/255))<.01);
});
test('threshold, invert and dithering preserve average tone',()=>{
 const flat=v=>new Float32Array(64*64).fill(v);
 assert.deepEqual([...core.monochrome(Float32Array.from([0,127,128,255]),4,1,{method:'threshold'})],[0,0,1,1]);
 assert.deepEqual([...core.monochrome(Float32Array.from([0,127,128,255]),4,1,{method:'threshold',threshold:200,invert:true})],[1,1,1,0]);
 const share=(level,method)=>{const bits=core.monochrome(flat(level),64,64,{method});return bits.reduce((a,b)=>a+b,0)/bits.length;};
 for(const level of [32,128,200]) assert.ok(Math.abs(share(level,'floyd')-level/255)<.02,'floyd '+level);
 // Atkinson diffuses only 6/8 of the error, so it keeps mid-tones but crushes deep shadows by design.
 assert.ok(Math.abs(share(128,'atkinson')-.5)<.05);assert.equal(share(32,'atkinson'),0);
 const input=flat(100);core.monochrome(input,64,64,{method:'floyd'});assert.equal(input[5],100,'source gray must not be mutated');
 assert.throws(()=>core.monochrome(flat(1),64,64,{method:'nope'}),/Unknown/);
});
test('target size keeps aspect ratio and validates width',()=>{
 assert.deepEqual({...core.targetSize(4000,3000,0)},{width:4000,height:3000});
 assert.deepEqual({...core.targetSize(4000,3000,400)},{width:400,height:300});
 assert.deepEqual({...core.targetSize(4000,10,1)},{width:1,height:1});
 for(const w of [-1,0.2,20001]) assert.throws(()=>core.targetSize(10,10,w),/Width/);
});

// Independent reference: PBKDF2 → AES-256-CTR keystream (slot number in the upper 64 counter bits) → bit-exact
// rejection sampling → partial Fisher–Yates over the slot's half of the pool (even or odd pool indices).
function referencePositions(passphrase,salt,pixelCount,slot,key=pbkdf2Sync(passphrase,salt,600000,32,'sha256')){
 const iv=Buffer.alloc(16);iv.writeBigUInt64BE(BigInt(slot),0);
 const stream=createCipheriv('aes-256-ctr',key,iv);
 let bytes=Buffer.alloc(0),pos=0,bitPos=0;
 const bit=()=>{if(pos>=bytes.length){bytes=stream.update(Buffer.alloc(4096));pos=0;}const b=(bytes[pos]>>(7-bitPos))&1;if(++bitPos===8){bitPos=0;pos++;}return b;};
 const uniform=n=>{if(n<=1)return 0;const w=(n-1).toString(2).length;for(;;){let v=0;for(let i=0;i<w;i++)v=v*2+bit();if(v<n)return v;}};
 const size=Math.floor((pixelCount-128-slot+1)/2),pool=Array.from({length:size},(_,i)=>i),out=[];
 for(let i=0;i<264;i++){const j=i+uniform(size-i);[pool[i],pool[j]]=[pool[j],pool[i]];out.push(128+2*pool[i]+slot);}
 return out;
}
const dithered=(w,h,seed=1)=>{const g=new Float32Array(w*h);for(let i=0;i<g.length;i++){seed=(seed*1103515245+12345)>>>0;g[i]=(i%w)*255/w*.6+(seed>>>24)*.4;}return core.monochrome(g,w,h,{method:'floyd'});};

test('payload parsing: ASCII 8 bits per char, hex 4 bits per digit, 264-bit cap',()=>{
 assert.deepEqual([...core.payloadBits('A',0)],[0,1,0,0,0,0,0,1]);
 assert.deepEqual([...core.payloadBits('0 f\n1',1)],[0,0,0,0, 1,1,1,1, 0,0,0,1]);
 assert.equal(core.payloadBits('a'.repeat(33),0).length,264);assert.equal(core.payloadBits('0'.repeat(66),1).length,264);
 assert.throws(()=>core.payloadBits('a'.repeat(34),0),/272 bits; at most 264/);
 assert.throws(()=>core.payloadBits('0'.repeat(67),1),/268 bits/);
 assert.throws(()=>core.payloadBits('café',0),/Only ASCII/);assert.throws(()=>core.payloadBits('😀',0),/Only ASCII/);
 for(const bad of ['0x1','g','12:34']) assert.throws(()=>core.payloadBits(bad,1),/Hex input/);
 for(const empty of ['',' \n']) assert.throws(()=>core.payloadBits(empty,1),/Enter data/);
 assert.equal(core.formatHex(core.payloadBits('00aF7',1)),'00af7');
 assert.equal(core.formatAscii(core.unpackBits(Uint8Array.from([72,105,10,0,200,127,9]))),'Hi\n···\t');
});

test('the record is exactly 264 bits: payload first, then fresh random padding, with no header or checksum',()=>{
 const payload=core.payloadBits('0004f2a9c'+'e'.repeat(24),1);
 const a=core.buildRecord(payload),b=core.buildRecord(payload);
 assert.equal(a.length,264);assert.deepEqual([...a.subarray(0,132)],[...payload]);assert.deepEqual([...b.subarray(0,132)],[...payload]);
 assert.notDeepEqual([...a.subarray(132)],[...b.subarray(132)],'padding is random each time');
 assert.deepEqual([...core.buildRecord(core.payloadBits('f'.repeat(66),1))],Array(264).fill(1));
 assert.equal(core.HIDE.recordBits,264);assert.equal('headerBits' in core.HIDE,false);
 assert.doesNotMatch(coreScript,/digest\(|SHA-256'\s*,\s*data/,'no checksum is computed');
});

test('round trips ASCII, odd-length hex with leading zeros and the 264-bit maximum through a BMP file, in either slot',async()=>{
 const w=100,h=60;
 for(const [type,text] of [[0,'Meet at dawn ~ 42!'],[1,'0'.repeat(10)+'abc'+'1'.repeat(20)],[1,'f'.repeat(66)],[0,'z'.repeat(33)]]){
  for(const slot of [0,1]){
   const bits=dithered(w,h,text.length+slot),secrets=[null,null];secrets[slot]={payload:core.payloadBits(text,type),passphrase:'pass phrase'};
   const info=await core.hideInBitmap(bits,secrets);
   assert.ok(info.changed<=128+2*264);
   const out=await core.extractFromBitmap(Uint8Array.from(readBmp(core.encodeBmp(bits,w,h)).pixels),'pass phrase');
   assert.equal(out.slots.length,2);for(const s of out.slots){assert.equal(s.bits.length,264);assert.equal(s.hex.length,66);assert.equal(s.ascii.length,33);}
   assert.ok((type?out.slots[slot].hex:out.slots[slot].ascii).startsWith(text));
  }
 }
});

test('two secrets with their own passphrases never collide and each is recovered from its own slot',async()=>{
 const w=30,h=22;assert.equal(core.MIN_PIXELS,656);assert.ok(w*h>=656);
 const decoy='1'.repeat(66),real=Array.from({length:66},(_,i)=>'0123456789abcdef'[(i*7+3)%16]).join('');
 const original=dithered(w,h,4),bits=original.slice(),salt=Uint8Array.from({length:16},(_,i)=>i*13+1);
 const info=await core.hideInBitmap(bits,[{payload:core.payloadBits(decoy,1),passphrase:'decoy'},{payload:core.payloadBits(real,1),passphrase:'real 🔑'}],salt);
 for(let k=0;k<128;k++) assert.equal(bits[k],(salt[k>>3]>>(7-(k&7)))&1);
 const p0=referencePositions('decoy',salt,w*h,0),p1=referencePositions('real 🔑',salt,w*h,1);
 assert.deepEqual([...info.slots[0].positions],p0);assert.deepEqual([...info.slots[1].positions],p1);
 assert.ok(p0.every(p=>(p-128)%2===0)&&p1.every(p=>(p-128)%2===1));assert.equal(new Set([...p0,...p1]).size,528,'no shared pixels');
 const touched=new Set([...Array.from({length:128},(_,i)=>i),...p0,...p1]);
 let changed=0;for(let p=0;p<bits.length;p++){if(bits[p]!==original[p])changed++;if(!touched.has(p))assert.equal(bits[p],original[p],'untouched pixel '+p+' changed');}
 assert.equal(changed,info.changed);
 assert.equal((await core.extractFromBitmap(bits,'decoy')).slots[0].hex,decoy);
 assert.equal((await core.extractFromBitmap(bits,'real 🔑')).slots[1].hex,real);
 await assert.rejects(core.hideInBitmap(bits.slice(),[{payload:core.payloadBits('a',0),passphrase:'same'},{payload:core.payloadBits('b',0),passphrase:'same'}]),/different passphrase/);
 await assert.rejects(core.hideInBitmap(bits.slice(),[null,null]),/at least one secret/);
 const clash=Uint32Array.from({length:264},(_,i)=>200+i);
 assert.throws(()=>core.writeHidden(bits.slice(),salt,[{positions:clash,record:new Uint8Array(264)},{positions:clash.map(p=>p+250),record:new Uint8Array(264)}]),/share 14 pixels\. Choose a different passphrase/);
});

test('an empty slot is filled with random bits at random positions in its own half',async()=>{
 const w=40,h=30,salt=new Uint8Array(16);
 const a=dithered(w,h),b=a.slice();
 const ia=await core.hideInBitmap(a,[{payload:core.payloadBits('ab',1),passphrase:'p'}],salt);
 const ib=await core.hideInBitmap(b,[{payload:core.payloadBits('ab',1),passphrase:'p'}],salt);
 assert.deepEqual([...ia.slots[0].positions],[...ib.slots[0].positions],'slot 1 positions depend only on passphrase and salt');
 assert.notDeepEqual([...ia.slots[1].positions],[...ib.slots[1].positions],'random-fill positions differ every time');
 assert.ok([...ia.slots[1].positions].every(p=>(p-128)%2===1));
 const fill=ia.slots[1].record,ones=fill.reduce((x,y)=>x+y,0);assert.ok(ones>90&&ones<174,'random fill looks uniform: '+ones);
 ia.slots[1].positions.forEach((p,k)=>assert.equal(a[p],fill[k]));
});

test('any passphrase yields two 264-bit slots with the same shape, deterministically',async()=>{
 const bits=dithered(60,40);await core.hideInBitmap(bits,[{payload:core.payloadBits('c0ffee',1),passphrase:'right'}]);
 const right=await core.extractFromBitmap(bits,'right');assert.ok(right.slots[0].hex.startsWith('c0ffee'));
 for(const [image,pass] of [[bits,'wrong'],[dithered(60,40,5),'right']]){
  const out=await core.extractFromBitmap(image,pass);
  assert.deepEqual(Object.keys(out.slots[0]),Object.keys(right.slots[0]));
  const salt=core.packBits(image.subarray(0,128)),key=pbkdf2Sync(pass,salt,600000,32,'sha256');
  for(const slot of [0,1]){assert.match(out.slots[slot].hex,/^[0-9a-f]{66}$/);assert.deepEqual([...out.slots[slot].bits],referencePositions(pass,salt,image.length,slot,key).map(p=>image[p]));}
  assert.deepEqual(await core.extractFromBitmap(image,pass),out,'deterministic');
 }
 await assert.rejects(core.hideInBitmap(new Uint8Array(655),[{payload:core.payloadBits('a',0),passphrase:'p'}]),/at least 656 pixels/);
 await core.hideInBitmap(new Uint8Array(656),[{payload:core.payloadBits('a',0),passphrase:'p'},{payload:core.payloadBits('b',0),passphrase:'q'}]);
 await assert.rejects(core.extractFromBitmap(new Uint8Array(655),'p'),/fewer than 656 pixels/);
});

test('data URLs round trip and reject malformed input',()=>{
 const bytes=Uint8Array.from({length:70000},(_,i)=>(i*31)&255);
 const url=core.toDataUrl('image/webp',bytes);
 assert.match(url,/^data:image\/webp;base64,/);assert.equal(url.slice(23),Buffer.from(bytes).toString('base64'));
 const parsed=core.parseDataUrl(' '+url.slice(0,500)+'\n'+url.slice(500)+'\n');
 assert.equal(parsed.mime,'image/webp');assert.deepEqual(Buffer.from(parsed.bytes),Buffer.from(bytes));
 for(const bad of ['','UklGRiQA','data:image/webp;base64,','data:image/jpeg;base64,AAAA','data:image/webp;base64,AAA','data:text/html;base64,AAAA','data:image/webp,AAAA']) assert.throws(()=>core.parseDataUrl(bad),/complete data URL/);
});
test('QR codes use byte mode, honour the selected error correction level and enforce version 40 capacity',()=>{
 const header='data:image/webp;base64,';
 for(const [level,cap] of Object.entries({L:2953,M:2331,Q:1663,H:1273})){
  assert.equal(core.QR_CAPACITY[level],cap);
  const fits=header+'A'.repeat(cap-header.length);
  assert.equal(core.makeQr(fits,level).getModuleCount(),177,level+' at capacity is version 40');
  assert.throws(()=>core.makeQr(fits+'A',level),new RegExp('at level '+level+' holds at most'));
 }
 const small=header+'UklGRiQAAABXRUJQVlA4TBgAAAAvAAAAAA==';
 const sizes=['L','M','Q','H'].map(level=>core.makeQr(small,level).getModuleCount());
 assert.ok(sizes[0]<=sizes[3] && sizes[3]>sizes[0],'higher correction needs a larger code: '+sizes);
 assert.throws(()=>core.makeQr(small,'X'),/Unknown/);
});
