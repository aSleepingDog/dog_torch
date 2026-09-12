const dog_torch = require('./build/Release/dog_torch_napi.node');
console.log(dog_torch)
//binary
var bin = new dog_torch.BinaryData("hello",0)
var ori = bin.toString()
console.log(ori)

var bis = bin.toBinaryString()
console.log(bis)

var hex = bin.toHexString(false)
console.log(hex)

var Hex = bin.toHexString(true)
console.log(Hex)

var bas = bin.toBase64String("+","/","=")
console.log(bas)

bin = new dog_torch.BinaryData(ori,0)
console.log(bin.toString())

bin = new dog_torch.BinaryData(bis,1)
console.log(bin.toString())

bin = new dog_torch.BinaryData(hex,2)
console.log(bin.toString())

bin = new dog_torch.BinaryData(Hex,2)
console.log(bin.toString())

bin = new dog_torch.BinaryData(bas,3)
console.log(bin.toString())

//number_region
var region = "";
try{
    region = new dog_torch.NumberIterator("")
}
catch(e){
    console.log(e)
}

region = new dog_torch.NumberIterator("28,32|48,64");
while(region.haveNext()){
    console.log(region.next())
}

try{
    region.haveNext();
}catch(e){
    console.log(e)
}

try{
    region.next();
}catch(e){
    console.log(e)
}

region = new dog_torch.NumberIterator("[16,32|8]");
while(region.haveNext()){
    console.log(region.next())
}
//crypto
console.log("crypto")
console.log(dog_torch.crypto.ParamType.Bool)
console.log(dog_torch.crypto.ParamType[0])
console.log(dog_torch.crypto.ParamType.UInt64)
console.log(dog_torch.crypto.ParamType[1])
console.log(dog_torch.crypto.ParamType.String)
console.log(dog_torch.crypto.ParamType[2])
console.log(dog_torch.crypto.ParamType.Binary)
console.log(dog_torch.crypto.ParamType[3])
console.log(dog_torch.crypto.ParamType.Hash)
console.log(dog_torch.crypto.ParamType[4])

//crypto hash
dog_torch.crypto.hash.all().forEach((config)=>{
    console.log(typeof(config));
    console.log(config.name);
    console.log(config.region);
    region = new dog_torch.NumberIterator(config.region);
    while(region.haveNext()){
        console.log(region.next())
    }
    console.log(config.params);
    Object.entries(config.params).forEach(([k,v])=>{
        console.log(k);
        console.log(v);
        console.log(v.type);
        console.log(v.msg);
    })
})

let alg = dog_torch.crypto.hash.create("SHA2",256,{});
if(alg!==undefined){
    console.log(alg.fmtString());
}

let sha2 = dog_torch.crypto.hash.SHA2(256);
console.log(sha2.fmtString());
let gen0 = new dog_torch.crypto.hash.Generator(sha2);
console.log(gen0.calcuateBinary(new dog_torch.BinaryData("hello",0)).toHexString(true));
console.log(gen0.calcuateFile(__filename).toHexString(true));

let sm3 = dog_torch.crypto.hash.SM3();
console.log(sm3.fmtString());
gen0 = new dog_torch.crypto.hash.Generator(sm3);
console.log(gen0.fmtString());
console.log(gen0.calcuateBinary(new dog_torch.BinaryData("hello",0)).toHexString(true));
console.log(gen0.calcuateFile(__filename).toHexString(true));

let blake2 = dog_torch.crypto.hash.BLAKE2(64,{});
console.log(blake2.fmtString());
gen0 = new dog_torch.crypto.hash.Generator(blake2);
console.log(gen0.fmtString());
console.log(gen0.calcuateBinary(new dog_torch.BinaryData("hello",0)).toHexString(true));
console.log(gen0.calcuateFile(__filename).toHexString(true));

//sym stream
dog_torch.crypto.sym.stream.algorithm.all().forEach(
    (config)=>{
        console.log(config.name);
        console.log(config.effectiveRegion);
        console.log(config.keyRegion);
    }
)

alg = dog_torch.crypto.sym.stream.algorithm.create("ChaCha",20,0)
console.log(alg.fmtString());

let chacha = dog_torch.crypto.sym.stream.algorithm.ChaCha(20);
console.log(chacha.fmtString());
let cipher0 = new dog_torch.crypto.sym.stream.Cipher(chacha);
console.log(cipher0.fmtString());

let key = new dog_torch.BinaryData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",0);

plain = new dog_torch.BinaryData("hellohellohellohellohellohellohellohellohellohellohello",0);

cipher0.setKey(key);
cipher0.init();
let cryp0 = cipher0.encrypt(plain);
console.log(cryp0.toHexString(true));
let plai0 = cipher0.decrypt(cryp0);
console.log(plai0.toString());
let hc = dog_torch.BinaryData.concat(cipher0.serialize(),cryp0);
console.log(hc.toHexString(true));
let tset = dog_torch.crypto.sym.stream.parse(hc);
tset.cipher.setKey(key);
tset.cipher.init();
plai0 = tset.cipher.decrypt(cryp0,tset.length);
console.log(plai0.toString());


//sym block
dog_torch.crypto.sym.block.algorithm.all().forEach(
    (config)=>{
        console.log(config.name);
        console.log(config.blockRegion);
        console.log(config.keyRegion);
        let blockr = new dog_torch.NumberIterator(config.blockRegion);
        while(blockr.haveNext()){
            let keyr = new dog_torch.NumberIterator(config.keyRegion);
            while(keyr.haveNext()){
                let alg = dog_torch.crypto.sym.block.algorithm.create(config.name,blockr.next(),keyr.next());
                console.log(alg.fmtString());
            }
        }  
    }
);

dog_torch.crypto.sym.block.mode.all().forEach(
    (config)=>{
        console.log(config.name);
        Object.entries(config.params).forEach(([k,v])=>{
            console.log(k);
            console.log(dog_torch.crypto.ParamType[v.type]);
            console.log(v.msg);
        })
    }
)

dog_torch.crypto.sym.block.padding.all().forEach(
    (config)=>{
        console.log(config);
        let padding = dog_torch.crypto.sym.block.padding.create(config);
        console.log(padding.fmtString());
    }
)

let mode_params = {
    iv: new dog_torch.BinaryData("dfghjkl;askjlhkdgfashhjd",0),
    shift: 0,
    aad: new dog_torch.BinaryData("dfghjkl;askjlhkdgfashhjd",0),
    tag_out: 0
}
let padding = dog_torch.crypto.sym.block.padding.PKCS7();
console.log(padding.fmtString());

dog_torch.crypto.sym.block.mode.all().forEach(
    (mode_config)=>{
        console.log(mode_config.name);
        let mode = dog_torch.crypto.sym.block.mode.create(mode_config.name,padding,mode_params);
        dog_torch.crypto.sym.block.algorithm.all().forEach(
            (config)=>{
                let blockr = new dog_torch.NumberIterator(config.blockRegion);
                while(blockr.haveNext()){
                    let keyr = new dog_torch.NumberIterator(config.keyRegion);
                    while(keyr.haveNext()){
                        let alg = dog_torch.crypto.sym.block.algorithm.create(config.name,blockr.next(),keyr.next());
                        console.log(alg.fmtString());
                        let cipher = new dog_torch.crypto.sym.block.Cipher(alg,mode);
                        console.log(cipher.fmtString());
                        cipher.setKey(key);
                        cipher.init();
                        let cryp0 = cipher.encrypt(plain);
                        console.log(cryp0.toHexString(true));
                        let plai0 = cipher.decrypt(cryp0);
                        console.log(plai0.toString());
                        console.log(plai0.toHexString(true)===plain.toHexString(true));
                        
                        let header = cipher.serialize();
                        console.log(header.toHexString(true));
                        let set = dog_torch.crypto.sym.block.parse(header);
                        console.log(set.length);
                        console.log(set.cipher.fmtString());
                        console.log(set.cipher.fmtString()===cipher.fmtString());

                        let hecry = dog_torch.BinaryData.concat(header,cryp0);
                        let set0 = dog_torch.crypto.sym.block.parse(hecry);
                        set0.cipher.setKey(key);
                        set0.cipher.init();
                        let plai1 = set0.cipher.decrypt(hecry,set0.length);
                        console.log(plai1.toString());
                        console.log(plai1.toHexString(true)===plain.toHexString(true))

                        console.log();
                    }
                }  
            }
        );
    }
)

function transParam(output){
    if(output.type===0 || output.type===1){
        return new dog_torch.BinaryParams(output.type);
    }
    else if(output.type===2){
        return new dog_torch.BinaryParams(output.type,output.isUpper);
    }
    else if(output.type===3){
        return new dog_torch.BinaryParams(output.type,output.replace0,output.replace1,output.replace2);
    }
    return null;
}
var taskPool = new dog_torch.async.ThreadPool();
gen0 = new dog_torch.crypto.hash.Generator(sha2);
taskPool.start();
taskPool.addHashTask(gen0,__filename,transParam({type:2,isUpper:true}));

console.log(taskPool.taskDetails());
setTimeout(()=>{
    console.log(taskPool.taskDetails());
    taskPool.wait();
    console.log(taskPool.taskResults());
},1000);
let key0 = new dog_torch.BinaryData("0123456789ABCDEF",0);
taskPool.addDecryptTask(key0,"E:/output.enc","E:/plain.mp4")
setTimeout(()=>{
    taskPool.wait();
    console.log(taskPool.taskResults());
},1000);