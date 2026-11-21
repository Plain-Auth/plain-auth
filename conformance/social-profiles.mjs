// Regenerate the authorization and userinfo contracts by executing the pinned
// provider implementations against local HTTP response fixtures.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { socialProviders } from "better-auth/social-providers";

const email = "person@example.org", image = "https://images.example.org/person.jpg";
const base = { email, name: "Person", picture: image, email_verified: true };
const inputs = {
  atlassian: {...base,account_id:"atlassian-sub"},
  facebook: {id:"fb-person",email,name:"Facebook Person",picture:{data:{url:image}}},
  twitter: {data:{id:"x-person",name:"X Person",profile_image_url:image}},
  vk: {user:{user_id:"vk-person",email,first_name:"VK",last_name:"Person",avatar:image}},
  tiktok: {data:{user:{open_id:"tiktok-person",display_name:"TikTok Person",avatar_large_url:image}}},
  wechat: {openid:"wechat-open",unionid:"wechat-person",nickname:"WeChat Person",headimgurl:image},
  cloudflare: {success:true,result:{id:"cf-sub",email,first_name:"A",last_name:"Person"}},
  kakao: {id:1024,kakao_account:{email,is_email_valid:true,is_email_verified:true,profile:{nickname:"Kakao Person",thumbnail_image_url:image}}},
  line: {...base,sub:"line-sub"},
  notion: {bot:{owner:{user:{id:"notion-id",name:"Notion Person",avatar_url:image,person:{email}}}}},
  paypal: {...base,user_id:"paypal-id"},
  discord: {id:"80351110224678912",username:"person",global_name:"A Person",email,verified:true,avatar:"a_example",discriminator:"0"},
  dropbox: {account_id:"dbid:abc",name:{display_name:"A Person"},email,email_verified:true,profile_photo_url:image},
  figma: {id:"figma-sub",handle:"figma-name",email,img_url:image},
  gitlab: {id:123456,name:"GitLab Person",email,email_verified:true,avatar_url:image,state:"active",locked:false},
  huggingface: {...base,sub:"hf-sub",name:"",preferred_username:"hf-person"},
  kick: {data:[{user_id:481,name:"Kick Person",email,profile_picture:image}]},
  linear: {data:{viewer:{id:"linear-sub",name:"Linear Person",email,avatarUrl:image}}},
  linkedin: {...base,sub:"li-sub"},
  naver: {resultcode:"00",response:{id:"nav-sub",nickname:"Naver Person",email,profile_image:image}},
  polar: {id:"polar-id",public_name:"Polar Person",email,email_verified:true,avatar_url:image},
  railway: {...base,sub:"railway-sub"},
  reddit: {id:"abcdef",name:"Reddit Person",icon_img:image+"?size=32"},
  roblox: {sub:"1234567",nickname:"Roblox Person",picture:image},
  salesforce: {user_id:"sf-sub",name:"Salesforce Person",email,email_verified:true,photos:{thumbnail:image}},
  slack: {...base,sub:"irrelevant","https://slack.com/user_id":"U0001"},
  spotify: {id:"sp-sub",display_name:"Spotify Person",email,images:[{url:image}]},
  vercel: {...base,sub:"vc-sub"},
  zoom: {id:"zm-sub",display_name:"Zoom Person",email,verified:1,pic_url:image},
};
const configs = {}, examples = {};
const clientId = "fixture-client", clientSecret = "fixture-secret";
const redirectURI = "https://app.example.org/api/auth/callback/provider";
const codeVerifier = "fixture-verifier-that-is-long-enough-for-standard-pkce";
for (const [id, data] of Object.entries(inputs)) {
  let calls = [];
  let payload;
  globalThis.fetch = async (input, options) => {
    const req = new Request(input, options);
    calls.push({url:req.url,method:req.method,headers:Object.fromEntries(req.headers),body:await req.text()});
    if(req.url.includes("debug_token"))return Response.json({data:{is_valid:true,app_id:clientId,user_id:data.id}});
    if(req.url.includes("user.fields=confirmed_email"))return Response.json({data:{confirmed_email:email}});
    return Response.json(payload);
  };
  const p = socialProviders[id](id==="tiktok"?{clientKey:clientId,clientSecret}:{clientId,clientSecret});
  const target=await p.createAuthorizationURL({state:"shared-state",nonce:"nonce",codeVerifier,redirectURI});
  payload={access_token:"fixture-access",token_type:"Bearer",expires_in:3600,openid:"wechat-open",scope:"snsapi_login"};
  await p.validateAuthorizationCode({code:"code",codeVerifier,redirectURI,deviceId:"fixture-device"});
  const token=calls.at(-1);
  calls=[];
  payload=data;
  const identity=await p.getUserInfo({accessToken:"fixture-access",tokenType:"Bearer",openid:"wechat-open"});
  assert.ok(identity,id);
  const info=calls.find(r => !r.url.includes("debug_token") && !r.url.includes("user.fields=confirmed_email"));
  const auth=new URL(target);
  const scopes=(auth.searchParams.get("scope")??"").split(" ").filter(Boolean);
  const pkce=auth.searchParams.has("code_challenge");
  for(const field of ["response_type","scope","client_id","client_key","appid","redirect_uri","state","nonce","code_challenge","code_challenge_method"])auth.searchParams.delete(field);
  const params=Object.fromEntries(auth.searchParams);auth.search="";
  let post;
  if(token.headers["content-type"]?.includes("application/json"))post=JSON.parse(token.body);
  else post=Object.fromEntries(new URLSearchParams(token.body));
  const tokenURL=new URL(token.url), profileURL=new URL(info.url);
  if(id==="wechat") {tokenURL.search="";profileURL.search="";}
  const config={authorization:auth.href,token:tokenURL.href,profile:profileURL.href,method:info.method,pkce,scopes,params,
    basic:!!token.headers.authorization,tokenJSON:token.headers["content-type"]?.includes("application/json")||false};
  if(info.body && id!=="vk")config.profileBody=info.body;
  if(info.headers["notion-version"])config.headers={"Notion-Version":info.headers["notion-version"]};
  if((post.grant_type??new URL(token.url).searchParams.get("grant_type"))!=="authorization_code")throw new Error(id+" unsupported exchange");
  if(p.refreshAccessToken){
    calls=[];
    payload={access_token:"new-access",refresh_token:"new-refresh",token_type:"Bearer",scope:"read",expires_in:3600,openid:"wechat-open"};
    await p.refreshAccessToken("sample-refresh");
    const request=calls[0];
    const endpoint=new URL(request.url);
    const fields=new URLSearchParams(request.body || endpoint.search);
    endpoint.search="";
    config.refresh={url:endpoint.href,method:request.method,basic:!!request.headers.authorization,fields:[...fields.keys()].sort()};
  }
  configs[id]=config;
  const subject=await p.accountSubject({profile:identity.data,tokens:{accessToken:"fixture-access"}});
  examples[id]={input:data,expectedData:identity.data,expected:{subject:String(subject),name:identity.user.name,email:identity.user.email,
    image:identity.user.image??null,emailVerified:identity.user.emailVerified}};
}
const issuers = {};
for (const id of ["cognito", "paybin", "twitch"]) {
  const options = {clientId, clientSecret, domain:"auth.fixture.example.org", region:"us-east-2", userPoolId:"us-east-2_abcdef"};
  const data = {...base, sub:id+"-subject", name:"", given_name:"Cognito Person", preferred_username:"Preferred Person"};
  const encoded = Buffer.from(JSON.stringify(data)).toString("base64url");
  const raw = "eyJhbGciOiJSUzI1NiJ9."+encoded+".eA";
  let request;
  globalThis.fetch = async(input,init) => {
    request=new Request(input,init);
    return Response.json({access_token:"fixture-access",id_token:raw,token_type:"Bearer"});
  };
  const provider = socialProviders[id](options);
  const target = await provider.createAuthorizationURL({state:"fixture",codeVerifier,redirectURI});
  await provider.validateAuthorizationCode({code:"fixture",codeVerifier,redirectURI});
  const profile = await provider.getUserInfo({idToken:raw, accessToken:"fixture-access"});
  const auth = new URL(target);
  const scope=auth.searchParams.get("scope"), pkce=auth.searchParams.has("code_challenge"), claims=auth.searchParams.get("claims");
  auth.search="";
  issuers[id]={authorization:auth.href,token:request.url,scope,pkce,claims,input:data,expected:{
    subject:String(await provider.accountSubject({profile:profile.data,tokens:{idToken:raw}})),
    email:profile.user.email,emailVerified:profile.user.emailVerified,name:profile.user.name,image:profile.user.image
  }};
}
for(const [name,value] of Object.entries({"catalog.json":configs,"testdata/catalog.json":examples,"testdata/issuers.json":issuers})){
  const file=new URL("../providers/"+name,import.meta.url);
  const text=JSON.stringify(value,null,2)+"\n";
  if(process.argv.includes("--write"))await writeFile(file,text);
  else assert.equal(await readFile(file,"utf8"),text,name);
}
