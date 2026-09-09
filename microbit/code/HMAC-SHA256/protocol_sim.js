// End-to-end simulation using the EXACT packet byte-layouts from the three
// hardened .ts programs, to catch offset/reassembly bugs (not just crypto).
const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
const rotr=(x,n)=>((x>>>n)|(x<<(32-n)))>>>0;
function sha256(bytes){let H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];let m=bytes.slice();let l=bytes.length;m.push(0x80);while(m.length%64!==56)m.push(0);m.push(0,0,0,0);const bl=(l*8)>>>0;m.push((bl>>>24)&255,(bl>>>16)&255,(bl>>>8)&255,bl&255);const W=new Array(64);for(let off=0;off<m.length;off+=64){for(let t=0;t<16;t++)W[t]=((m[off+4*t]<<24)|(m[off+4*t+1]<<16)|(m[off+4*t+2]<<8)|m[off+4*t+3])>>>0;for(let t=16;t<64;t++){const s0=(rotr(W[t-15],7)^rotr(W[t-15],18)^(W[t-15]>>>3))>>>0;const s1=(rotr(W[t-2],17)^rotr(W[t-2],19)^(W[t-2]>>>10))>>>0;W[t]=(((W[t-16]+s0)>>>0)+((W[t-7]+s1)>>>0))>>>0;}let a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];for(let t=0;t<64;t++){const S1=(rotr(e,6)^rotr(e,11)^rotr(e,25))>>>0;const ch=((e&f)^((~e)&g))>>>0;const t1=(((h+S1)>>>0)+((ch+((K[t]+W[t])>>>0))>>>0))>>>0;const S0=(rotr(a,2)^rotr(a,13)^rotr(a,22))>>>0;const maj=((a&b)^(a&c)^(b&c))>>>0;const t2=(S0+maj)>>>0;h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;}H[0]=(H[0]+a)>>>0;H[1]=(H[1]+b)>>>0;H[2]=(H[2]+c)>>>0;H[3]=(H[3]+d)>>>0;H[4]=(H[4]+e)>>>0;H[5]=(H[5]+f)>>>0;H[6]=(H[6]+g)>>>0;H[7]=(H[7]+h)>>>0;}const o=[];for(let i=0;i<8;i++)o.push((H[i]>>>24)&255,(H[i]>>>16)&255,(H[i]>>>8)&255,H[i]&255);return o;}
function hmac(key,msg){const B=64;let k=key.slice();if(k.length>B)k=sha256(k);while(k.length<B)k.push(0);const ip=[],op=[];for(let i=0;i<B;i++){ip.push(k[i]^0x36);op.push(k[i]^0x5c);}return sha256(op.concat(sha256(ip.concat(msg))));}
const take=(a,n)=>a.slice(0,n);
const u32=x=>[(x>>>24)&255,(x>>>16)&255,(x>>>8)&255,x&255];
let pass=0,fail=0;const ck=(n,g,w)=>{const ok=g===w;console.log((ok?'PASS ':'FAIL ')+n);ok?pass++:fail++;};

const CELL=1;
const CELLKEY=[0x8f,0x21,0x6c,0xa3,0x0b,0xd4,0x77,0x19,0xe2,0x55,0x3a,0x90,0xc1,0x4e,0x88,0x02];
const DAYKEY =[0xc7,0x96,0x63,0x2a,0x11,0xff,0x01,0x58,0x49,0x40,0x6f,0xde,0x21,0xbe,0x07,0x80];
const SERIAL_LEGIT=0xDEADBEEF, SERIAL_SPY=0x13370001;

// ---- SENDER builds P1, P2 exactly as in whisper-sender-hardened.ts ----
const IV=[11,22,33,44,55,66,77,88];
let ksIn=[0x00]; for(let i=0;i<8;i++)ksIn.push(IV[i]);
const ks=hmac(CELLKEY,ksIn);
const C=[]; for(let i=0;i<16;i++)C.push(DAYKEY[i]^ks[i]);
let tagIn=[0x01]; for(let i=0;i<8;i++)tagIn.push(IV[i]); for(let i=0;i<16;i++)tagIn.push(C[i]);
const tag=take(hmac(CELLKEY,tagIn),8);
const P1=new Array(18).fill(0); P1[0]=1;P1[1]=CELL; for(let i=0;i<8;i++)P1[2+i]=IV[i]; for(let i=0;i<8;i++)P1[10+i]=C[i];
const P2=new Array(18).fill(0); P2[0]=2;P2[1]=CELL; for(let i=0;i<8;i++)P2[2+i]=C[8+i]; for(let i=0;i<8;i++)P2[10+i]=tag[i];

// ---- RESPONDER parses P1,P2 exactly as in whisper-responder-hardened.ts ----
let seedIV=[],seedC=new Array(16).fill(0),seedTag=[];
// P1
for(let i=0;i<8;i++)seedIV[i]=P1[2+i]; for(let i=0;i<8;i++)seedC[i]=P1[10+i];
// P2
for(let i=0;i<8;i++)seedC[8+i]=P2[2+i]; for(let i=0;i<8;i++)seedTag[i]=P2[10+i];
// verify tag
let tIn=[0x01]; for(let i=0;i<8;i++)tIn.push(seedIV[i]); for(let i=0;i<16;i++)tIn.push(seedC[i]);
const t=take(hmac(CELLKEY,tIn),8);
ck('wire: seed tag verifies after reassembly', JSON.stringify(t), JSON.stringify(seedTag));
// decrypt
let kIn=[0x00]; for(let i=0;i<8;i++)kIn.push(seedIV[i]);
const ks2=hmac(CELLKEY,kIn);
const recovered=[]; for(let i=0;i<16;i++)recovered.push(seedC[i]^ks2[i]);
ck('wire: responder recovers DAYKEY', JSON.stringify(recovered), JSON.stringify(DAYKEY));

// ---- CHECKER challenge, RESPONDER answer (legit), CHECKER verify ----
const nonce=[9,8,7,6,5,4,3,2,1,0,255,254];
// responder computes
function respond(daykey,serial){let mIn=[0x02];for(let i=0;i<12;i++)mIn.push(nonce[i]);const sb=u32(serial);for(let i=0;i<4;i++)mIn.push(sb[i]);return take(hmac(daykey,mIn),12);}
function verify(key,serial,mac){let mIn=[0x02];for(let i=0;i<12;i++)mIn.push(nonce[i]);const sb=u32(serial);for(let i=0;i<4;i++)mIn.push(sb[i]);const exp=take(hmac(key,mIn),12);return JSON.stringify(exp)===JSON.stringify(mac);}

const legitMac=respond(DAYKEY,SERIAL_LEGIT);
ck('wire: legit response accepted', verify(DAYKEY,SERIAL_LEGIT,legitMac)?'accept':'reject','accept');
ck('wire: relayed response (spy serial) rejected', verify(DAYKEY,SERIAL_SPY,legitMac)?'accept':'reject','reject');
const spyGuess=respond([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],SERIAL_SPY); // no key
ck('wire: forgery without key rejected', verify(DAYKEY,SERIAL_SPY,spyGuess)?'accept':'reject','reject');
const thiefMac=respond(DAYKEY,SERIAL_SPY); // stole DAYKEY, uses own serial
ck('wire: genuine key theft earns +5', verify(DAYKEY,SERIAL_SPY,thiefMac)?'accept':'reject','accept');

// packet sizes
ck('P1 size <= 19', String(P1.length<=19),'true');
ck('P2 size <= 19', String(P2.length<=19),'true');

console.log('\n'+pass+' passed, '+fail+' failed');
process.exit(fail?1:0);
