const fs=require('fs');
let js=fs.readFileSync(process.argv[2],'utf8');
const handlers={};
var paths=[];
var box={getBoundingClientRect:()=>({left:0,top:0,width:1000,height:392})};
function el(id){return {id,style:{},dataset:{},innerHTML:'',offsetWidth:266,offsetHeight:180,
  classList:{add(){},remove(){}},querySelector:()=>null,querySelectorAll:()=>paths,
  setAttribute(k,v){this['a_'+k]=v;},getAttribute(k){return this['a_'+k]||null;},
  addEventListener(t,f){(handlers[id]=handlers[id]||{})[t]=f;},
  getBoundingClientRect:()=>({left:0,top:0,width:1000,height:392}),
  scrollIntoView(){},parentNode:box};}
const els={};
['attackmap','maptip','mapdet','attacktop','mzin','mzout','mzrst'].forEach(k=>els[k]=el(k));
// paths simulados: uno por pais, incluido uno SIN codigo (data-iso="") -> el bug del borde negro
function fakePath(iso){return {a:{'data-iso':iso},cls:{},getAttribute(k){return this.a[k];},
  classList:{add:function(c){this.o.cls[c]=1;},remove:function(c){delete this.o.cls[c];}}};}
['US','NL','ML',''].forEach(iso=>{const p=fakePath(iso);p.classList.o=p;paths.push(p);});
global.window={__ATTACK_GEO:{US:12,NL:4,ML:2},__ATTACK_TOTAL:18,
  __ATTACK_DET:{US:{ips:[['203.0.113.7',9]],ports:[['443/tcp',10]],srcs:[['192.0.2.10',8]],nip:14,npt:5,nsr:3},
                NL:{ips:[['203.0.113.44',4]],ports:[['8080/tcp',4]],srcs:[['192.0.2.11',4]],nip:1,npt:1,nsr:1},
                ML:{ips:[['203.0.113.90',2]],ports:[['22/tcp',2]],srcs:[['192.0.2.12',2]],nip:1,npt:1,nsr:1}},
  __ATTACK_HOME:[-78.1,-1.8],addEventListener(){}};
global.document={getElementById:id=>els[id]||null,addEventListener(){}};
global.topojson={feature:()=>({features:[
  {id:840,properties:{name:'United States of America'},geometry:{type:'Polygon',coordinates:[[[-120,50],[-70,50],[-70,25],[-120,25],[-120,50]]]}},
  {id:528,properties:{name:'Netherlands'},geometry:{type:'Polygon',coordinates:[[[4,53],[7,53],[7,51],[4,51],[4,53]]]}},
  {id:466,properties:{name:'Mali'},geometry:{type:'Polygon',coordinates:[[[-12,25],[4,25],[4,10],[-12,10],[-12,25]]]}},
  {id:-99,properties:{name:'Kosovo'},geometry:{type:'Polygon',coordinates:[[[20,43],[22,43],[22,42],[20,42],[20,43]]]}}]})};
global.fetch=()=>Promise.resolve({json:()=>Promise.resolve({objects:{countries:{}}})});
process.on('unhandledRejection',e=>{console.log('REJECT:',e&&e.message,e&&e.stack);});
try{eval(js);}catch(e){console.log('THROW:',e.message);console.log(e.stack.split('\n').slice(0,4).join('\n'));process.exit(1);}
setTimeout(()=>{
  const svg=els.attackmap,out=svg.innerHTML;
  if(!out.length){console.log('SVG vacio');process.exit(1);}
  ['data-iso="US"','data-iso="ML"','data-iso="XK"','animateMotion'].forEach(m=>{
    if(out.indexOf(m)<0)throw new Error('falta en el SVG: '+m);});
  console.log('render OK: incluye paises antes ausentes (ML) y Kosovo (XK)');
  handlers.attackmap.click({target:{getAttribute:k=>k==='data-iso'?'NL':null}});
  const selNL=paths.filter(p=>p.cls.sel).map(p=>p.a['data-iso']);
  if(selNL.join()!=='NL')throw new Error('seleccion incorrecta al hacer clic: '+JSON.stringify(selNL));
  console.log('clic marca solo el pais elegido:',selNL);
  handlers.mzrst.click();
  const selTras=paths.filter(p=>p.cls.sel).map(p=>p.a['data-iso']);
  if(selTras.length)throw new Error('BUG: Vista completa dejo marcados: '+JSON.stringify(selTras));
  console.log('Vista completa NO deja ningun borde negro (bug corregido)');
  if(svg.getAttribute('viewBox')!=='0.0 20.0 1000.0 392.0')throw new Error('no restablece la vista');
  handlers.attackmap.mousemove({target:{getAttribute:k=>k==='data-iso'?'ML':null},clientX:400,clientY:200});
  ['Mali','203.0.113.90','22/tcp'].forEach(m=>{
    if(els.maptip.innerHTML.indexOf(m)<0)throw new Error('falta en tooltip: '+m);});
  console.log('pais sin traduccion usa el nombre del mapa (Mali) y trae su detalle');
  if(els.attacktop.innerHTML.indexOf('Mali')<0)throw new Error('el Top no muestra el nombre');
  console.log('Top paises con nombre correcto');
  console.log('TODO OK');
},80);
